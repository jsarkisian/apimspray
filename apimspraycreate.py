#!/usr/bin/env python3
"""
apimspraycreate.py - Azure APIM Proxy Deployment (Python Version)
Replicates functionality of apimsprayrotator.sh
"""

import argparse
import subprocess
import sys
import time
import os
import shutil
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed

# Colors
class Colors:
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    RESET = '\033[0m'

DEFAULT_RG_LOCATION = "germanywestcentral"

def log(level, message):
    if level == "info":
        print(f"{Colors.BLUE}[INFO]{Colors.RESET} {message}")
    elif level == "ok":
        print(f"{Colors.GREEN}[ OK ]{Colors.RESET} {message}")
    elif level == "warn":
        print(f"{Colors.YELLOW}[WARN]{Colors.RESET} {message}")
    elif level == "error":
        print(f"{Colors.RED}[ERR ]{Colors.RESET} {message}")

def die(message):
    log("error", message)
    sys.exit(1)

def run_command(command, check=True, capture_output=True, timeout=None):
    try:
        result = subprocess.run(
            command,
            check=check,
            shell=True,
            text=True,
            capture_output=capture_output,
            timeout=timeout
        )
        return result.stdout.strip() if result.stdout else ""
    except subprocess.CalledProcessError as e:
        if check:
            raise e
        return None

def retry_command(command, attempts=15, delay=10):
    for i in range(attempts):
        try:
            return run_command(command)
        except subprocess.CalledProcessError:
            if i < attempts - 1:
                # log("warn", f"Command failed, retrying in {delay}s... ({i+1}/{attempts})")
                time.sleep(delay)
            else:
                raise

def get_az_regions():
    cmd = (
        "az provider show --namespace Microsoft.ApiManagement "
        "--query \"resourceTypes[?resourceType=='service'].locations[]\" "
        "-o tsv"
    )
    output = run_command(cmd)
    if not output:
        return []
    # Clean up and normalize
    regions = [r.strip().replace(" ", "").lower() for r in output.split('\n') if r.strip()]
    return regions

def normalize_location(value):
    return value.strip().replace(" ", "").lower()

def parse_location_list(value):
    if value is None:
        return []
    return [normalize_location(part) for part in value.split(",") if part.strip()]

def deploy_instance(index, location, resource_group, timestamp, prefix, realm_prefix, backend_url, product_id, tmp_dir):
    apim_name = f"apimspray-created-apim-{timestamp}-Number-{index}"
    api_id = "oauth"
    realm_api_id = "userrealm"
    url_file = os.path.join(tmp_dir, f"{apim_name}.url")
    
    try:
        log("info", f"[{apim_name}] Creating APIM instance in {location}...")
        run_command(f"az apim create --name {apim_name} --resource-group {resource_group} --location {location} --publisher-name Proxy --publisher-email proxy@example.com --sku-name Consumption --no-wait")

        log("info", f"[{apim_name}] Waiting for deployment...")
        run_command(f"az apim wait --name {apim_name} --resource-group {resource_group} --created --interval 10 --timeout 1800")

        log("info", f"[{apim_name}] Creating OAuth API...")
        retry_command(f"az apim api create --service-name {apim_name} --resource-group {resource_group} --api-id {api_id} --path {prefix} --display-name OAuth --protocols https --api-type http --service-url {backend_url}")

        log("info", f"[{apim_name}] Ensuring product exists...")
        try:
            retry_command(f"az apim product show --resource-group {resource_group} --service-name {apim_name} --product-id {product_id}", attempts=3, delay=5)
        except:
            retry_command(f"az apim product create --resource-group {resource_group} --service-name {apim_name} --product-id {product_id} --product-name apimspray --subscription-required false --state published")

        log("info", f"[{apim_name}] Attaching API to product...")
        retry_command(f"az apim product api add --resource-group {resource_group} --service-name {apim_name} --product-id {product_id} --api-id {api_id}")

        log("info", f"[{apim_name}] Creating logon operation...")
        retry_command(f"az apim api operation create --resource-group {resource_group} --service-name {apim_name} --api-id {api_id} --operation-id logon --url-template /common/oauth2/token --method POST --display-name logon")

        # Get Gateway URL
        service_url = retry_command(f"az apim show --name {apim_name} --resource-group {resource_group} --query gatewayUrl -o tsv")
        final_url = f"{service_url}/{prefix}"
        
        # User Realm logic could be added here similar to bash script if needed, but the main goal is apimspray urls
        # Bash script adds userrealm. Let's add it for parity.
        
        log("info", f"[{apim_name}] Creating UserRealm API...")
        retry_command(f"az apim api create --service-name {apim_name} --resource-group {resource_group} --api-id {realm_api_id} --path {realm_prefix} --display-name UserRealm --protocols https --api-type http --service-url {backend_url}")

        log("info", f"[{apim_name}] Attaching UserRealm API...")
        retry_command(f"az apim product api add --resource-group {resource_group} --service-name {apim_name} --product-id {product_id} --api-id {realm_api_id}")

        log("info", f"[{apim_name}] Creating userrealm operation...")
        retry_command(f"az apim api operation create --resource-group {resource_group} --service-name {apim_name} --api-id {realm_api_id} --operation-id userrealm --url-template /getuserrealm.srf --method GET --display-name userrealm")

        # Write URL to file
        with open(url_file, "w") as f:
            f.write(f"{final_url}/\n")
        
        log("ok", f"[{apim_name}] Ready at {final_url}/")
        return (index, location, True)

    except Exception as e:
        log("error", f"[{apim_name}] Failed: {e}")
        return (index, location, False)

def main():
    parser = argparse.ArgumentParser(description="apimspraycreate - Azure APIM Deployer")
    parser.add_argument("--outfile", required=True, help="Output file for URLs")
    parser.add_argument("--count", type=int, help="Number of instances")
    parser.add_argument(
        "--location",
        help=(
            "Comma-separated APIM location(s) to deploy into. When provided, only those "
            "regions are used and the first location is used for the resource group."
        ),
    )
    parser.add_argument("--prefix", default="oauth", help="API URL prefix")
    parser.add_argument("--realm-prefix", default="realm", help="Realm API prefix")
    parser.add_argument("--delete-old", action="store_true", help="Delete old resource groups")
    
    args = parser.parse_args()

    # Check AZ
    try:
        run_command("az account show")
    except:
        die("Azure CLI not logged in. Run: az login")

    # Get Regions
    log("info", "Fetching available APIM regions...")
    available_regions = get_az_regions()
    if not available_regions:
        die("No APIM regions found")
    
    log("ok", f"Discovered {len(available_regions)} regions")

    target_regions = available_regions
    rg_location = DEFAULT_RG_LOCATION

    if args.location:
        requested_regions = parse_location_list(args.location)
        if not requested_regions:
            die("No valid locations provided. Use comma-separated list, e.g. --location westeurope,germanynorth")
        invalid = []
        for loc in requested_regions:
            if loc not in available_regions and loc not in invalid:
                invalid.append(loc)
        if invalid:
            available_display = ", ".join(sorted(available_regions))
            die(f"Unknown APIM region(s): {', '.join(invalid)}. Available regions: {available_display}")
        target_regions = requested_regions
        rg_location = requested_regions[0]
        log("info", f"Using requested APIM locations: {', '.join(target_regions)}")

    count = args.count if args.count else len(target_regions)
    if count > len(target_regions):
        if args.location:
            log("warn", f"Requested count {count} exceeds selected regions {len(target_regions)}. Locations will repeat.")
        else:
            log("warn", f"Requested count {count} exceeds regions {len(target_regions)}. Limiting.")
            count = len(target_regions)
    
    if count < 1 or count > 199:
        die("Count must be between 1 and 199")

    # Config
    timestamp = int(time.time())
    resource_group = f"apim-rotator-{timestamp}"
    backend_url = "https://login.microsoftonline.com"
    product_id = "apimspray-product"
    
    # Cleanup
    if args.delete_old:
        log("info", "Checking for old resource groups...")
        try:
            old_groups = run_command("az group list --query \"[?starts_with(name, 'apim-rotator-')].name\" -o tsv")
            if old_groups:
                for grp in old_groups.split():
                    if grp != resource_group:
                        log("info", f"Deleting {grp}...")
                        run_command(f"az group delete --name {grp} --yes --no-wait")
        except:
            pass

    # Create RG
    log("info", f"Creating Resource Group: {resource_group}")
    run_command(f"az group create --name {resource_group} --location {rg_location} --tags createdBy=apim-proxy")
    log("ok", "Resource Group Ready")

    # Deploy
    tmp_dir = tempfile.mkdtemp()
    futures = []
    
    with ThreadPoolExecutor(max_workers=count) as executor:
        for i in range(1, count + 1):
            region = target_regions[(i - 1) % len(target_regions)]
            futures.append(executor.submit(
                deploy_instance, i, region, resource_group, timestamp, args.prefix, args.realm_prefix, backend_url, product_id, tmp_dir
            ))
            
    # Wait
    successful_regions = []
    failed_regions = []
    
    for f in as_completed(futures):
        idx, reg, success = f.result()
        if success:
            successful_regions.append(reg)
        else:
            failed_regions.append(reg)

    # Collect URLs
    with open(args.outfile, 'w') as f_out:
        for i in range(1, count + 1):
            fname = os.path.join(tmp_dir, f"apimspray-created-apim-{timestamp}-Number-{i}.url")
            if os.path.exists(fname):
                with open(fname, 'r') as f_in:
                    f_out.write(f_in.read())

    shutil.rmtree(tmp_dir)

    print("-" * 40)
    print(f"Resource Group : {resource_group}")
    print(f"Instances      : {count}")
    print(f"Successful     : {len(successful_regions)}")
    print(f"Failed         : {len(failed_regions)}")
    print(f"URLs written   : {args.outfile}")
    print("-" * 40)
    
    if failed_regions:
        log("warn", "Some deployments failed.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        die("Interrupted")
