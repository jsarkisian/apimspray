#!/usr/bin/env python3
"""
apimspraycreate_teams.py - Azure APIM Proxy Deployment for Teams API
Deploys APIM instances that proxy requests to https://teams.microsoft.com/api/mt/
for use with apimspray --mode enumerate --teams-urls
"""

import argparse
import subprocess
import sys
import time
import os
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
            command, check=check, shell=True, text=True,
            capture_output=capture_output, timeout=timeout
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
    regions = [r.strip().replace(" ", "").lower() for r in output.split('\n') if r.strip()]
    return regions

def normalize_location(value):
    return value.strip().replace(" ", "").lower()

def parse_location_list(value):
    if value is None:
        return []
    return [normalize_location(part) for part in value.split(",") if part.strip()]

def deploy_instance(index, location, resource_group, timestamp, prefix, backend_url, product_id):
    """
    Deploy a single APIM instance that proxies the Teams API.
    The key difference from the login deployer:
      - backend_url is https://teams.microsoft.com/api/mt
      - The operation uses a wildcard GET path to handle /{region}/beta/users/{email}/externalsearchv3
    """
    apim_name = f"apimteams-created-apim-{timestamp}-Number-{index}"
    api_id = "teamsapi"

    try:
        log("info", f"[{apim_name}] Creating APIM instance in {location}...")
        retry_command(
            f"az apim create --name {apim_name} --resource-group {resource_group} "
            f"--location {location} --publisher-name TeamsProxy --publisher-email proxy@example.com "
            "--sku-name Consumption --no-wait",
            attempts=3, delay=20,
        )

        log("info", f"[{apim_name}] Waiting for deployment...")
        retry_command(
            f"az apim wait --name {apim_name} --resource-group {resource_group} "
            "--created --interval 10 --timeout 1800",
            attempts=3, delay=20,
        )

        log("info", f"[{apim_name}] Creating Teams API...")
        retry_command(
            f"az apim api create --service-name {apim_name} --resource-group {resource_group} "
            f"--api-id {api_id} --path {prefix} --display-name TeamsAPI --protocols https "
            f"--api-type http --service-url {backend_url}"
        )

        log("info", f"[{apim_name}] Ensuring product exists...")
        try:
            retry_command(
                f"az apim product show --resource-group {resource_group} "
                f"--service-name {apim_name} --product-id {product_id}",
                attempts=3, delay=5,
            )
        except Exception:
            retry_command(
                f"az apim product create --resource-group {resource_group} "
                f"--service-name {apim_name} --product-id {product_id} "
                f"--product-name apimteams --subscription-required false --state published"
            )

        log("info", f"[{apim_name}] Attaching API to product...")
        retry_command(
            f"az apim product api add --resource-group {resource_group} "
            f"--service-name {apim_name} --product-id {product_id} --api-id {api_id}"
        )

        # Create a wildcard operation to handle all GET requests under the prefix.
        # This handles paths like: /{region}/beta/users/{email}/externalsearchv3
        # Using a catch-all URL template with a wildcard parameter.
        log("info", f"[{apim_name}] Creating wildcard enum operation (GET)...")
        retry_command(
            f"az apim api operation create --resource-group {resource_group} "
            f"--service-name {apim_name} --api-id {api_id} "
            f'--operation-id enumuser --url-template "/*" --method GET '
            f'--display-name "Teams User Enum"'
        )

        # Get Gateway URL
        service_url = retry_command(
            f"az apim show --name {apim_name} --resource-group {resource_group} "
            "--query gatewayUrl -o tsv"
        )
        final_url = f"{service_url}/{prefix}"

        log("ok", f"[{apim_name}] Ready at {final_url}/")
        return (index, location, True, f"{final_url}/")

    except Exception as e:
        log("error", f"[{apim_name}] Failed: {e}")
        return (index, location, False, None)


def main():
    parser = argparse.ArgumentParser(description="apimspraycreate_teams - Azure APIM Deployer for Teams API")
    parser.add_argument("--outfile", required=True, help="Output file for Teams APIM URLs")
    parser.add_argument("--count", type=int, help="Number of instances to deploy")
    parser.add_argument(
        "--location",
        help="Comma-separated APIM location(s) to deploy into.",
    )
    parser.add_argument("--prefix", default="teamsmt", help="API URL prefix (default: teamsmt)")
    parser.add_argument("--delete-old", action="store_true", help="Delete old Teams APIM resource groups")
    parser.add_argument(
        "--backend-url",
        default="https://teams.microsoft.com/api/mt",
        help="Teams API backend URL (default: https://teams.microsoft.com/api/mt)",
    )

    args = parser.parse_args()

    # Check AZ
    try:
        run_command("az account show")
    except Exception:
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
            die("No valid locations provided.")
        invalid = [loc for loc in requested_regions if loc not in available_regions]
        if invalid:
            die(f"Unknown APIM region(s): {', '.join(invalid)}")
        target_regions = requested_regions
        rg_location = requested_regions[0]
        log("info", f"Using requested APIM locations: {', '.join(target_regions)}")

    count = args.count if args.count else len(target_regions)
    if count > len(target_regions):
        log("warn", f"Requested count {count} exceeds regions {len(target_regions)}. Locations will repeat.")
    if count < 1:
        die("Count must be at least 1")

    timestamp = int(time.time())
    resource_group = f"apim-teams-rotator-{timestamp}"
    product_id = "apimteams-product"

    # Cleanup
    if args.delete_old:
        log("info", "Checking for old Teams resource groups...")
        try:
            old_groups = run_command("az group list --query \"[?starts_with(name, 'apim-teams-rotator-')].name\" -o tsv")
            if old_groups:
                for grp in old_groups.split():
                    if grp != resource_group:
                        log("info", f"Deleting {grp}...")
                        run_command(f"az group delete --name {grp} --yes --no-wait")
        except Exception:
            pass

    # Create RG
    log("info", f"Creating Resource Group: {resource_group}")
    run_command(f"az group create --name {resource_group} --location {rg_location} --tags createdBy=apim-teams-proxy")
    log("ok", "Resource Group Ready")

    # Deploy
    max_workers = min(32, count)
    max_total_attempts = max(count * 3, count + 10)
    next_index = 1
    urls = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        while len(urls) < count and next_index <= max_total_attempts:
            remaining = count - len(urls)
            batch_size = min(max_workers, remaining, max_total_attempts - next_index + 1)
            futures = []
            for _ in range(batch_size):
                region = target_regions[(next_index - 1) % len(target_regions)]
                futures.append(executor.submit(
                    deploy_instance, next_index, region, resource_group,
                    timestamp, args.prefix, args.backend_url, product_id
                ))
                next_index += 1
            for f in as_completed(futures):
                idx, reg, success, url = f.result()
                if success:
                    urls.append(url)

    if len(urls) < count:
        log("error", f"Only created {len(urls)} of {count} instances after retries.")

    with open(args.outfile, 'w') as f_out:
        for url in urls:
            f_out.write(f"{url}\n")

    print("-" * 40)
    print(f"Resource Group : {resource_group}")
    print(f"Instances      : {count}")
    print(f"Successful     : {len(urls)}")
    print(f"Backend        : {args.backend_url}")
    print(f"URLs written   : {args.outfile}")
    print("-" * 40)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        die("Interrupted")
