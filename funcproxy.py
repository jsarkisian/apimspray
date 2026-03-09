#!/usr/bin/env python3
"""
funcproxy.py - Deploy Azure Functions as HTTP proxies to Teams API.
Each Function App in a different region gets its own outbound IP,
providing IP diversity for Teams enumeration.
"""

import argparse
import json
import os
import subprocess
import sys
import threading
import tempfile
import time
import zipfile

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

DEFAULT_REGIONS = [
    "eastus", "westeurope", "japaneast", "australiaeast",
    "southeastasia", "northeurope", "westus2", "centralindia",
    "brazilsouth", "canadacentral", "uksouth", "koreacentral",
    "francecentral", "switzerlandnorth", "norwayeast",
]

RG_PREFIX = "funcproxy-"
APP_PREFIX = "funcproxy-"


def create_zip_package():
    """Create a zip of func_template/ for deployment."""
    template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "func_template")
    if not os.path.isdir(template_dir):
        die(f"Function template not found at {template_dir}")

    tmp = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
    zip_path = tmp.name
    tmp.close()
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(template_dir):
            for f in files:
                full = os.path.join(root, f)
                arcname = os.path.relpath(full, template_dir)
                zf.write(full, arcname)
    return zip_path


def deploy(regions, outfile, prefix):
    """Deploy one Function App per region."""
    timestamp = int(time.time())
    rg_name = f"{RG_PREFIX}{timestamp}"
    rg_location = regions[0]

    # Validate az login
    try:
        run_command("az account show")
    except Exception:
        die("Azure CLI not logged in. Run: az login")

    # Ensure Microsoft.Web provider is registered
    reg_state = run_command(
        "az provider show --namespace Microsoft.Web --query registrationState -o tsv",
        check=False,
    )
    if reg_state and reg_state.strip() != "Registered":
        log("info", "Registering Microsoft.Web resource provider...")
        run_command("az provider register --namespace Microsoft.Web")
        for _ in range(30):
            time.sleep(5)
            state = run_command(
                "az provider show --namespace Microsoft.Web --query registrationState -o tsv",
                check=False,
            )
            if state and state.strip() == "Registered":
                break
        else:
            die("Microsoft.Web provider did not register in time. "
                "Run: az provider register --namespace Microsoft.Web")
        log("ok", "Microsoft.Web provider registered")

    # Create resource group
    log("info", f"Creating Resource Group: {rg_name} in {rg_location}")
    run_command(f"az group create --name {rg_name} --location {rg_location} "
                f"--tags createdBy=funcproxy")
    log("ok", "Resource Group ready")

    # Create zip package
    zip_path = create_zip_package()
    log("ok", "Function package created")

    # Deploy all regions in parallel
    results = [None] * len(regions)
    errors = []
    lock = threading.Lock()
    completed = [0]

    def deploy_region(i, region):
        app_name = f"{prefix}{timestamp}-{i}"
        storage = f"fpstor{timestamp}{i}"
        storage = storage[:24]
        tag = f"[{i+1}/{len(regions)}] {region}"

        try:
            log("info", f"{tag}: Creating storage account...")
            run_command(
                f"az storage account create --name {storage} "
                f"--resource-group {rg_name} --location {region} "
                f"--sku Standard_LRS --kind StorageV2"
            )

            log("info", f"{tag}: Creating function app...")
            run_command(
                f"az functionapp create --name {app_name} "
                f"--resource-group {rg_name} "
                f"--storage-account {storage} "
                f"--consumption-plan-location {region} "
                f"--runtime python --runtime-version 3.11 "
                f"--functions-version 4 --os-type Linux"
            )

            log("info", f"{tag}: Deploying proxy code (remote build)...")
            run_command(
                f"az functionapp deployment source config-zip "
                f"--name {app_name} --resource-group {rg_name} "
                f"--src {zip_path} --build-remote true"
            )

            url = f"https://{app_name}.azurewebsites.net/api/"
            results[i] = url
            with lock:
                completed[0] += 1
                log("ok", f"{tag}: Ready ({completed[0]}/{len(regions)}) — {url}")
        except Exception as e:
            with lock:
                completed[0] += 1
                errors.append(region)
                log("error", f"{tag}: Failed ({completed[0]}/{len(regions)}) — {e}")

    log("info", f"Deploying {len(regions)} function apps in parallel...")
    threads = []
    for i, region in enumerate(regions):
        t = threading.Thread(target=deploy_region, args=(i, region))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

    os.unlink(zip_path)

    urls = [u for u in results if u is not None]
    if errors:
        log("warn", f"{len(errors)} region(s) failed: {', '.join(errors)}")

    # Write output file
    if outfile:
        with open(outfile, 'w') as f:
            for url in urls:
                f.write(f"{url}\n")
        log("ok", f"URLs written to {outfile}")

    # Summary
    print("-" * 40)
    print(f"Resource Group : {rg_name}")
    print(f"Function Apps  : {len(urls)}")
    print(f"Regions        : {', '.join(regions)}")
    if outfile:
        print(f"Output File    : {outfile}")
    print("-" * 40)
    print()
    for url in urls:
        print(url)

    return urls


def destroy():
    """Delete all funcproxy resource groups."""
    log("info", "Checking for funcproxy resource groups...")
    try:
        groups_json = run_command(
            f"az group list --query \"[?starts_with(name, '{RG_PREFIX}')].name\" -o json"
        )
        groups = json.loads(groups_json) if groups_json else []
    except Exception:
        groups = []

    if not groups:
        log("info", "No funcproxy resource groups found")
        return

    for grp in groups:
        log("info", f"Deleting {grp}...")
        run_command(f"az group delete --name {grp} --yes --no-wait")
    log("ok", f"Queued {len(groups)} resource group(s) for deletion")


def main():
    parser = argparse.ArgumentParser(
        description="funcproxy - Deploy Azure Functions as Teams API proxies",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("--deploy", action="store_true",
                        help="Deploy Function Apps across regions")
    parser.add_argument("--destroy", action="store_true",
                        help="Delete all funcproxy resource groups")
    parser.add_argument("--delete-old", action="store_true",
                        help="Delete old funcproxy resource groups before deploying")
    parser.add_argument("--regions", type=str, default=None,
                        help="Comma-separated regions (default: 15 diverse regions)")
    parser.add_argument("--count", type=int, default=None,
                        help="Number of regions to use (default: all specified regions)")
    parser.add_argument("--outfile", type=str, default=None,
                        help="Output file for Function URLs")
    parser.add_argument("--prefix", type=str, default=APP_PREFIX,
                        help="App name prefix (default: funcproxy-)")

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
    if args.count:
        regions = regions[:args.count]

    if not regions:
        die("No regions specified")

    deploy(regions, args.outfile, args.prefix)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        die("Interrupted")
