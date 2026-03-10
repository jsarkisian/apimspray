#!/usr/bin/env python3
"""
onedrive_proxy.py - Deploy Azure Container Instances as HTTP proxies for OneDrive user enumeration.
Each container gets a unique public Azure IP, enabling parallel enumeration across multiple IPs.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import threading
import time


class Colors:
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    RESET = '\033[0m'


def log(level, message):
    colors = {"info": Colors.BLUE, "ok": Colors.GREEN,
              "warn": Colors.YELLOW, "error": Colors.RED}
    labels = {"info": "[INFO]", "ok": "[ OK ]",
              "warn": "[WARN]", "error": "[ERR ]"}
    print(f"{colors.get(level, '')}{labels.get(level, '')}{Colors.RESET} {message}")


def die(message):
    log("error", message)
    sys.exit(1)


def run_command(command, check=True):
    try:
        result = subprocess.run(command, check=check, shell=True,
                                text=True, capture_output=True)
        return result.stdout.strip() if result.stdout else ""
    except subprocess.CalledProcessError as e:
        if check:
            if e.stderr:
                log("error", e.stderr.strip())
            raise
        return None


DEFAULT_REGIONS = ["eastus"]
RG_PREFIX = "odproxy-"
ACR_PREFIX = "odproxyreg"

UUID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE
)


def derive_sharepoint_host(tenant, domain=None):
    """
    Derive the SharePoint hostname from a tenant string.

    Examples:
      contoso.com             -> contoso-my.sharepoint.com
      contoso.onmicrosoft.com -> contoso-my.sharepoint.com
      contoso                 -> contoso-my.sharepoint.com
      <UUID>                  -> requires domain arg
    """
    if UUID_RE.match(tenant):
        if not domain:
            raise ValueError(
                "Tenant is a UUID — provide --domain to derive SharePoint hostname"
            )
        name = domain.split(".")[0]
    elif "." in tenant:
        name = tenant.split(".")[0]
    else:
        name = tenant
    return f"{name}-my.sharepoint.com"


def deploy(tenant, domain, regions, count, outfile):
    """Deploy ACI containers as OneDrive enum proxies."""
    sharepoint_host = derive_sharepoint_host(tenant, domain)
    timestamp = int(time.time())
    rg_name = f"{RG_PREFIX}{timestamp}"
    acr_name = f"{ACR_PREFIX}{timestamp}"
    rg_location = regions[0]

    try:
        run_command("az account show")
    except Exception:
        die("Azure CLI not logged in. Run: az login")

    reg_state = run_command(
        "az provider show --namespace Microsoft.ContainerInstance "
        "--query registrationState -o tsv", check=False)
    if reg_state and reg_state.strip() != "Registered":
        log("info", "Registering Microsoft.ContainerInstance provider...")
        run_command("az provider register --namespace Microsoft.ContainerInstance")
        for _ in range(30):
            time.sleep(5)
            state = run_command(
                "az provider show --namespace Microsoft.ContainerInstance "
                "--query registrationState -o tsv", check=False)
            if state and state.strip() == "Registered":
                break
        else:
            die("Microsoft.ContainerInstance provider did not register in time.")
        log("ok", "Provider registered")

    log("info", f"Target: {sharepoint_host}")
    log("info", f"Creating Resource Group: {rg_name} in {rg_location}")
    run_command(f"az group create --name {rg_name} --location {rg_location} "
                f"--tags createdBy=odproxy")
    log("ok", "Resource Group ready")

    log("info", f"Creating Container Registry: {acr_name}")
    run_command(f"az acr create --name {acr_name} --resource-group {rg_name} "
                f"--location {rg_location} --sku Basic --admin-enabled true")
    log("ok", "Container Registry ready")

    template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "aci_template")
    if not os.path.isdir(template_dir):
        die(f"Container template not found at {template_dir}")

    image_name = f"{acr_name}.azurecr.io/onedriveproxy:latest"
    log("info", "Building container image via ACR (remote build)...")
    run_command(f"az acr build --registry {acr_name} --resource-group {rg_name} "
                f"--image onedriveproxy:latest {template_dir}")
    log("ok", f"Image built: {image_name}")

    creds_json = run_command(
        f"az acr credential show --name {acr_name} --resource-group {rg_name} -o json")
    creds = json.loads(creds_json)
    acr_user = creds["username"]
    acr_pass = creds["passwords"][0]["value"]
    acr_server = f"{acr_name}.azurecr.io"

    results = [None] * count
    errors = []
    lock = threading.Lock()
    completed = [0]

    def deploy_container(i):
        region = regions[i % len(regions)]
        container_name = f"odproxy-{timestamp}-{i}"
        tag = f"[{i+1}/{count}] {region}"
        try:
            log("info", f"{tag}: Deploying container {container_name}...")
            run_command(
                f"az container create "
                f"--resource-group {rg_name} "
                f"--name {container_name} "
                f"--image {image_name} "
                f"--cpu 0.5 --memory 0.5 "
                f"--ports 8080 "
                f"--os-type Linux "
                f"--ip-address Public "
                f"--location {region} "
                f"--registry-login-server {acr_server} "
                f"--registry-username {acr_user} "
                f"--registry-password '{acr_pass}' "
                f"--environment-variables TARGET_HOST={sharepoint_host} "
                f"--restart-policy Never"
            )
            ip = run_command(
                f"az container show --resource-group {rg_name} "
                f"--name {container_name} "
                f"--query ipAddress.ip -o tsv"
            )
            if ip and ip.strip():
                url = f"http://{ip.strip()}:8080/"
                results[i] = url
                with lock:
                    completed[0] += 1
                    log("ok", f"{tag}: Ready ({completed[0]}/{count}) — {url}")
            else:
                with lock:
                    completed[0] += 1
                    errors.append(container_name)
                    log("error", f"{tag}: No IP assigned ({completed[0]}/{count})")
        except Exception as e:
            with lock:
                completed[0] += 1
                errors.append(container_name)
                log("error", f"{tag}: Failed ({completed[0]}/{count}) — {e}")

    log("info", f"Deploying {count} containers in parallel (target: {sharepoint_host})...")
    threads = []
    for i in range(count):
        t = threading.Thread(target=deploy_container, args=(i,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

    urls = [u for u in results if u is not None]
    if errors:
        log("warn", f"{len(errors)} container(s) failed: {', '.join(errors)}")

    if not urls:
        die("No containers deployed successfully")

    if outfile:
        with open(outfile, 'w') as f:
            for url in urls:
                f.write(f"{url}\n")
        log("ok", f"URLs written to {outfile}")

    print("-" * 40)
    print(f"Resource Group : {rg_name}")
    print(f"Registry       : {acr_name}")
    print(f"Target Host    : {sharepoint_host}")
    print(f"Containers     : {len(urls)}")
    print(f"Regions        : {', '.join(regions)}")
    if outfile:
        print(f"Output File    : {outfile}")
    print("-" * 40)
    for url in urls:
        print(url)

    return urls


def destroy():
    """Delete all odproxy resource groups."""
    log("info", "Checking for odproxy resource groups...")
    try:
        groups_json = run_command(
            f"az group list --query \"[?starts_with(name, '{RG_PREFIX}')].name\" -o json")
        groups = json.loads(groups_json) if groups_json else []
    except Exception:
        groups = []

    if not groups:
        log("info", "No odproxy resource groups found")
        return

    for grp in groups:
        log("info", f"Deleting {grp}...")
        run_command(f"az group delete --name {grp} --yes --no-wait")
    log("ok", f"Queued {len(groups)} resource group(s) for deletion")


def main():
    parser = argparse.ArgumentParser(
        description="onedrive_proxy - Deploy ACI containers for OneDrive user enumeration",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("--deploy", action="store_true",
                        help="Deploy ACI containers")
    parser.add_argument("--destroy", action="store_true",
                        help="Delete all odproxy resource groups")
    parser.add_argument("--delete-old", action="store_true",
                        help="Delete old odproxy resource groups before deploying")
    parser.add_argument("--tenant", type=str, default=None,
                        help="Target tenant/domain (e.g. contoso.com). Determines SharePoint host.")
    parser.add_argument("--domain", type=str, default=None,
                        help="Domain hint (required if --tenant is a UUID)")
    parser.add_argument("--regions", type=str, default=None,
                        help="Comma-separated regions (default: eastus)")
    parser.add_argument("--count", type=int, default=10,
                        help="Number of containers to deploy (default: 10)")
    parser.add_argument("--outfile", type=str, default=None,
                        help="Output file for proxy URLs")

    args = parser.parse_args()

    if args.destroy:
        destroy()
        return

    if args.delete_old:
        destroy()

    if not args.deploy:
        parser.print_help()
        return

    if not args.tenant:
        die("--tenant is required for deployment (e.g. --tenant contoso.com)")

    regions = DEFAULT_REGIONS
    if args.regions:
        regions = [r.strip().lower() for r in args.regions.split(",") if r.strip()]

    if not regions:
        die("No regions specified")

    deploy(args.tenant, args.domain, regions, args.count, args.outfile)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        die("Interrupted")
