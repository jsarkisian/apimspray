#!/usr/bin/env python3
"""
apimcreate.py - Unified Azure APIM Deployer (Bicep)
Deploys login and/or Teams APIM gateways in a single ARM deployment.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time

# Colors
class Colors:
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    RESET = '\033[0m'

def log(level, message):
    colors = {"info": Colors.BLUE, "ok": Colors.GREEN, "warn": Colors.YELLOW, "error": Colors.RED}
    labels = {"info": "[INFO]", "ok": "[ OK ]", "warn": "[WARN]", "error": "[ERR ]"}
    print(f"{colors.get(level, '')}{labels.get(level, '')}{Colors.RESET} {message}")

def die(message):
    log("error", message)
    sys.exit(1)

def run_command(command, check=True):
    try:
        result = subprocess.run(command, check=check, shell=True, text=True, capture_output=True)
        return result.stdout.strip() if result.stdout else ""
    except subprocess.CalledProcessError as e:
        if check:
            raise
        return None

DEFAULT_RG_LOCATION = "germanywestcentral"

def get_az_regions():
    cmd = (
        "az provider show --namespace Microsoft.ApiManagement "
        "--query \"resourceTypes[?resourceType=='service'].locations[]\" "
        "-o tsv"
    )
    output = run_command(cmd)
    if not output:
        return []
    return [r.strip().replace(" ", "").lower() for r in output.split('\n') if r.strip()]

def normalize_location(value):
    return value.strip().replace(" ", "").lower()

def parse_location_list(value):
    if value is None:
        return []
    return [normalize_location(part) for part in value.split(",") if part.strip()]

def main():
    parser = argparse.ArgumentParser(
        description="apimcreate - Unified Azure APIM Deployer (Bicep)",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--type", required=True, choices=["login", "teams", "both"],
        help="Type of APIM gateways to deploy:\n"
             " - login: proxies login.microsoftonline.com (for spray/validate)\n"
             " - teams: proxies teams.microsoft.com/api/mt (for enumerate)\n"
             " - both:  deploys login and teams gateways in one deployment",
    )
    parser.add_argument("--count", type=int, help="Number of instances per type")
    parser.add_argument("--outfile", help="Output file for login gateway URLs")
    parser.add_argument("--teams-outfile", help="Output file for Teams gateway URLs (required with --type both)")
    parser.add_argument(
        "--location",
        help="Comma-separated APIM location(s). First location used for resource group.",
    )
    parser.add_argument("--prefix", default=None, help="API URL prefix (default: oauth for login, teamsmt for teams)")
    parser.add_argument("--delete-old", action="store_true", help="Delete old resource groups before deploying")
    parser.add_argument("--delete-only", action="store_true", help="Only delete old resource groups")

    args = parser.parse_args()

    # Validate az login
    try:
        run_command("az account show")
    except Exception:
        die("Azure CLI not logged in. Run: az login")

    # Handle deletion
    if args.delete_only or args.delete_old:
        _delete_old_groups()
        if args.delete_only:
            return

    # Validate args for deployment
    deploy_login = args.type in ("login", "both")
    deploy_teams = args.type in ("teams", "both")

    if deploy_login and not args.outfile:
        die("--outfile is required for login gateway deployment")
    if deploy_teams and args.type == "both" and not args.teams_outfile:
        die("--teams-outfile is required with --type both")
    if deploy_teams and args.type == "teams" and not args.outfile and not args.teams_outfile:
        die("--outfile or --teams-outfile is required")

    # For --type teams with --outfile, treat outfile as teams output
    teams_outfile = args.teams_outfile or (args.outfile if args.type == "teams" else None)
    login_outfile = args.outfile if deploy_login else None

    # Discover regions
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

    count = args.count
    if not count:
        if args.location:
            count = len(target_regions)
        else:
            die("--count is required when --location is not specified")
    if count < 1:
        die("Count must be at least 1")
    if count > len(target_regions):
        log("warn", f"Requested count {count} exceeds regions {len(target_regions)}. Locations will repeat.")

    login_prefix = args.prefix or "oauth"
    teams_prefix = args.prefix or "teamsmt"

    # Build instance lists
    login_instances = []
    teams_instances = []
    timestamp = int(time.time())

    if deploy_login:
        for i in range(count):
            region = target_regions[i % len(target_regions)]
            login_instances.append({"index": i, "region": region})
        log("info", f"Will deploy {count} login APIM instance(s)")

    if deploy_teams:
        for i in range(count):
            region = target_regions[i % len(target_regions)]
            teams_instances.append({"index": i, "region": region})
        log("info", f"Will deploy {count} Teams APIM instance(s)")

    total = len(login_instances) + len(teams_instances)
    log("info", f"Total APIM instances: {total}")

    # Create resource group
    resource_group = f"apim-deploy-{timestamp}"
    log("info", f"Creating Resource Group: {resource_group}")
    run_command(f"az group create --name {resource_group} --location {rg_location} --tags createdBy=apimcreate")
    log("ok", "Resource Group Ready")

    # Generate and deploy Bicep
    bicep_content = generate_bicep(login_instances, teams_instances, timestamp, login_prefix, teams_prefix)

    with tempfile.NamedTemporaryFile(mode='w', suffix='.bicep', delete=False) as f:
        f.write(bicep_content)
        bicep_path = f.name

    try:
        log("info", f"Deploying {total} APIM instance(s) via Bicep (this may take 2-5 minutes)...")
        run_command(
            f"az deployment group create "
            f"--resource-group {resource_group} "
            f"--template-file {bicep_path} "
            f"--name apimcreate-{timestamp} "
            f"--no-wait false"
        )
        log("ok", "Deployment complete")
    except subprocess.CalledProcessError as e:
        die(f"Deployment failed: {e}")
    finally:
        os.unlink(bicep_path)

    # Extract gateway URLs from deployed resources
    login_urls, teams_urls = extract_gateway_urls(resource_group, timestamp, login_instances, teams_instances, login_prefix, teams_prefix)

    # Write output files
    if login_outfile and login_urls:
        with open(login_outfile, 'w') as f:
            for url in login_urls:
                f.write(f"{url}\n")
        log("ok", f"Login URLs written to {login_outfile}")

    if teams_outfile and teams_urls:
        with open(teams_outfile, 'w') as f:
            for url in teams_urls:
                f.write(f"{url}\n")
        log("ok", f"Teams URLs written to {teams_outfile}")

    # Summary
    print("-" * 40)
    print(f"Resource Group : {resource_group}")
    if login_urls:
        print(f"Login Gateways : {len(login_urls)}")
    if teams_urls:
        print(f"Teams Gateways : {len(teams_urls)}")
    print(f"Total          : {len(login_urls) + len(teams_urls)}")
    print("-" * 40)


def _delete_old_groups():
    log("info", "Checking for old resource groups...")
    deleted = 0
    for prefix in ("apim-rotator-", "apim-teams-rotator-", "apim-deploy-"):
        try:
            old_groups = run_command(
                f"az group list --query \"[?starts_with(name, '{prefix}')].name\" -o tsv"
            )
            if old_groups:
                for grp in old_groups.split():
                    log("info", f"Deleting {grp}...")
                    run_command(f"az group delete --name {grp} --yes --no-wait")
                    deleted += 1
        except Exception:
            pass
    if deleted > 0:
        log("ok", f"Queued {deleted} resource group(s) for deletion")
    else:
        log("info", "No old resource groups found")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        die("Interrupted")
