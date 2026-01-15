import argparse
import requests
import sys

def get_domains(target):
    # API endpoint based on user request
    url = f"https://azmap.dev/api/tenant?domain={target}&extract=true"
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        data = response.json()
        
        # Extract email_domains from the root of the JSON response
        domains = data.get('email_domains', [])
        
        # If the API returns a different structure or empty list, handle gracefully
        if not domains:
            # Fallback: sometimes APIs wrap results or return just the target if no others found
            print(f"[!] No extra domains found or API structure changed. Using target '{target}' if valid.")
            return [target] if '.' in target else []
            
        return domains
    except requests.exceptions.RequestException as e:
        print(f"[-] Error fetching domains from azmap.dev: {e}")
        sys.exit(1)
    except ValueError:
        print("[-] Error parsing JSON response from azmap.dev")
        sys.exit(1)

def get_usernames(url):
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        # Clean lines: remove whitespace, filter empty lines
        return [line.strip() for line in response.text.splitlines() if line.strip()]
    except requests.exceptions.RequestException as e:
        print(f"[-] Error fetching usernames from GitHub: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Generate UPNs from connected Azure Tenants and Service Accounts.")
    parser.add_argument("--target", required=True, help="Target Domain (e.g., example.com) or Tenant UUID")
    
    args = parser.parse_args()

    # 1. Collect connected domains
    print(f"[*] Querying connected domains for target: {args.target}")
    domains = get_domains(args.target)
    
    if not domains:
        print("[-] No domains found to process.")
        sys.exit(0)
        
    print(f"[+] Found {len(domains)} connected domains.")
    
    # 2. Fetch service account usernames
    user_list_url = "https://raw.githubusercontent.com/purpleracc00n/statistically-likely-usernames/refs/heads/master/service-accounts.txt"
    print(f"[*] Fetching service account usernames list...")
    usernames = get_usernames(user_list_url)
    print(f"[+] Retrieved {len(usernames)} usernames.")

    # 3. Generate UPNs
    print("[*] Generating UPN permutations...")
    upns = []
    for domain in domains:
        for username in usernames:
            upns.append(f"{username}@{domain}")

    # 4. Write to file
    outfile = "users.txt"
    try:
        with open(outfile, "w") as f:
            f.write("\n".join(upns) + "\n")
        print(f"[+] Successfully wrote {len(upns)} UPNs to '{outfile}'")
    except IOError as e:
        print(f"[-] Failed to write to file: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
