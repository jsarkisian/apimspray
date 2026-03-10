#!/usr/bin/env python3
"""
aciproxy.py - Deploy Azure Container Instances as HTTP proxies to Teams API.
Each container gets a dedicated public IP for guaranteed IP diversity.
"""

import argparse
import json
import os
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
RG_PREFIX = "aciproxy-"
ACR_PREFIX = "aciproxyreg"


def deploy(regions, count, outfile):
    """Deploy ACI containers as HTTP proxies."""
    timestamp = int(time.time())
    rg_name = f"{RG_PREFIX}{timestamp}"
    acr_name = f"{ACR_PREFIX}{timestamp}"
    rg_location = regions[0]

    # Validate az login
    try:
        run_command("az account show")
    except Exception:
        die("Azure CLI not logged in. Run: az login")

    # Ensure Microsoft.ContainerInstance provider is registered
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

    # Create resource group
    log("info", f"Creating Resource Group: {rg_name} in {rg_location}")
    run_command(f"az group create --name {rg_name} --location {rg_location} "
                f"--tags createdBy=aciproxy")
    log("ok", "Resource Group ready")

    # Create ACR
    log("info", f"Creating Container Registry: {acr_name}")
    run_command(f"az acr create --name {acr_name} --resource-group {rg_name} "
                f"--location {rg_location} --sku Basic --admin-enabled true")
    log("ok", "Container Registry ready")

    # Build and push image via ACR
    template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "aci_template")
    if not os.path.isdir(template_dir):
        die(f"Container template not found at {template_dir}")

    image_name = f"{acr_name}.azurecr.io/teamsproxy:latest"
    log("info", "Building container image via ACR (remote build)...")
    run_command(f"az acr build --registry {acr_name} --resource-group {rg_name} "
                f"--image teamsproxy:latest {template_dir}")
    log("ok", f"Image built: {image_name}")

    # Get ACR credentials
    creds_json = run_command(
        f"az acr credential show --name {acr_name} --resource-group {rg_name} -o json")
    creds = json.loads(creds_json)
    acr_user = creds["username"]
    acr_pass = creds["passwords"][0]["value"]
    acr_server = f"{acr_name}.azurecr.io"

    # Deploy containers in parallel
    results = [None] * count
    errors = []
    lock = threading.Lock()
    completed = [0]

    def deploy_container(i):
        region = regions[i % len(regions)]
        container_name = f"aciproxy-{timestamp}-{i}"
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
                f"--ip-address Public "
                f"--location {region} "
                f"--registry-login-server {acr_server} "
                f"--registry-username {acr_user} "
                f"--registry-password '{acr_pass}' "
                f"--restart-policy Never"
            )

            # Get public IP
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

    log("info", f"Deploying {count} containers in parallel...")
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

    # Write output file
    if outfile:
        with open(outfile, 'w') as f:
            for url in urls:
                f.write(f"{url}\n")
        log("ok", f"URLs written to {outfile}")

    # Summary
    print("-" * 40)
    print(f"Resource Group : {rg_name}")
    print(f"Registry       : {acr_name}")
    print(f"Containers     : {len(urls)}")
    print(f"Regions        : {', '.join(regions)}")
    if outfile:
        print(f"Output File    : {outfile}")
    print("-" * 40)
    print()
    for url in urls:
        print(url)

    return urls


def destroy():
    """Delete all aciproxy resource groups."""
    log("info", "Checking for aciproxy resource groups...")
    try:
        groups_json = run_command(
            f"az group list --query \"[?starts_with(name, '{RG_PREFIX}')].name\" -o json")
        groups = json.loads(groups_json) if groups_json else []
    except Exception:
        groups = []

    if not groups:
        log("info", "No aciproxy resource groups found")
        return

    for grp in groups:
        log("info", f"Deleting {grp}...")
        run_command(f"az group delete --name {grp} --yes --no-wait")
    log("ok", f"Queued {len(groups)} resource group(s) for deletion")


def main():
    parser = argparse.ArgumentParser(
        description="aciproxy - Deploy ACI containers as Teams API proxies",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("--deploy", action="store_true",
                        help="Deploy ACI containers")
    parser.add_argument("--destroy", action="store_true",
                        help="Delete all aciproxy resource groups")
    parser.add_argument("--delete-old", action="store_true",
                        help="Delete old aciproxy resource groups before deploying")
    parser.add_argument("--regions", type=str, default=None,
                        help="Comma-separated regions (default: eastus)")
    parser.add_argument("--count", type=int, default=15,
                        help="Number of containers to deploy (default: 15)")
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

    regions = DEFAULT_REGIONS
    if args.regions:
        regions = [r.strip().lower() for r in args.regions.split(",") if r.strip()]

    if not regions:
        die("No regions specified")

    deploy(regions, args.count, args.outfile)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        die("Interrupted")
