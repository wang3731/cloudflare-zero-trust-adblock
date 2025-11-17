#!/usr/bin/env python3
"""
AdGuard DNS Filter to Cloudflare Gateway Lists Converter

This script downloads the AdGuard DNS filter list and converts it to
domain lists compatible with Cloudflare Zero Trust Gateway Lists.
This allows you to create a SINGLE DNS policy that blocks all domains.
"""

import sys
import re
import requests
import csv
import ipaddress

# Cloudflare Gateway List limits
# Standard plans: 1,000 entries per list (or 2MB max file size)
# Enterprise plans: 5,000 entries per list (or 2MB max file size)
# Change this to 5000 if you have an Enterprise plan
MAX_DOMAINS_PER_LIST = 1000

# Default AdGuard DNS filter URL
DEFAULT_URL = "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/refs/heads/master/filters/filter_15_DnsFilter/filter.txt"

def is_valid_ip(value):
    """Check if a value is a valid IP address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def is_valid_domain(value):
    """Check if a value is a valid domain name (not an IP)."""
    if is_valid_ip(value):
        return False

    # Basic domain validation
    # Must contain at least one dot and valid characters
    if "." not in value:
        return False

    # Check for valid domain characters
    domain_pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')
    return bool(domain_pattern.match(value))

def parse_adguard_entry(line):
    """
    Parse AdGuard filter format and extract clean domain or IP.
    AdGuard format: ||domain.com^ or ||subdomain.domain.com^
    Returns tuple: (type, value) where type is 'domain' or 'ip'
    """
    line = line.strip()

    # Skip empty lines and comments
    if not line or line.startswith("!") or line.startswith("#"):
        return None, None

    # Extract domain/IP from AdGuard format ||domain^
    if line.startswith("||") and "^" in line:
        # Remove || prefix and everything after ^
        value = line[2:].split("^")[0]

        # Skip if it contains path separators or complex rules
        if "/" in value or "$" in line:
            return None, None

        # Skip wildcard domains (Cloudflare lists don't support wildcards)
        if "*" in value:
            return None, None

        # Determine if it's an IP or domain
        if is_valid_ip(value):
            return 'ip', value
        elif is_valid_domain(value):
            return 'domain', value
        else:
            return None, None

    return None, None

def process_input(input_source):
    """Process AdGuard filter list from URL or local file."""
    domains = []
    ips = []

    # Determine if input_source is a URL or a local file
    if input_source.startswith("http://") or input_source.startswith("https://"):
        try:
            print(f"Fetching filter list from: {input_source}")
            response = requests.get(input_source, timeout=30)
            response.raise_for_status()
            lines = response.text.splitlines()
            print(f"Downloaded {len(lines)} lines")
        except Exception as e:
            raise Exception(f"Failed to fetch URL: {e}")
    else:
        try:
            print(f"Reading from local file: {input_source}")
            with open(input_source, 'r', encoding='utf-8') as f:
                lines = f.read().splitlines()
            print(f"Read {len(lines)} lines")
        except Exception as e:
            raise Exception(f"Failed to read file: {e}")

    # Process each line
    for line in lines:
        entry_type, value = parse_adguard_entry(line)
        if entry_type == 'domain':
            domains.append(value)
        elif entry_type == 'ip':
            ips.append(value)

    # Remove duplicates while preserving order
    domains = list(dict.fromkeys(domains))
    ips = list(dict.fromkeys(ips))

    return domains, ips

def split_into_lists(domains, max_per_list):
    """Split domains into chunks suitable for Cloudflare lists."""
    lists = []
    for i in range(0, len(domains), max_per_list):
        lists.append(domains[i:i + max_per_list])
    return lists

def write_csv_lists(domain_lists, output_prefix="adguard_domains"):
    """Write domain lists as CSV files for Cloudflare import."""
    import os

    # Create lists directory if it doesn't exist
    os.makedirs("lists", exist_ok=True)

    files_created = []

    for idx, domain_list in enumerate(domain_lists):
        list_num = idx + 1
        filename = f"lists/{output_prefix}_{list_num}.csv"

        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            for domain in domain_list:
                writer.writerow([domain])

        files_created.append(filename)
        print(f"  - {filename}: {len(domain_list)} domains")

    return files_created

def write_api_script(num_lists, output_file="upload_lists.sh"):
    """Generate a bash script to upload lists via Cloudflare API."""
    script_content = '''#!/bin/bash
# Cloudflare Gateway Lists Upload Script
# This script uploads domain lists to Cloudflare Zero Trust

# Configuration - UPDATE THESE VALUES
ACCOUNT_ID="your-account-id"
API_TOKEN="your-api-token"

# Color output
GREEN='\\033[0;32m'
RED='\\033[0;31m'
NC='\\033[0m' # No Color

echo "Starting Cloudflare Gateway Lists upload..."
echo ""

# Create lists
'''

    for i in range(1, num_lists + 1):
        script_content += f'''
# Upload list {i}/{num_lists}
echo "Creating list {i}/{num_lists}..."
LIST_ID_{i}=$(curl -s -X POST "https://api.cloudflare.com/client/v4/accounts/${{ACCOUNT_ID}}/gateway/lists" \\
  -H "Authorization: Bearer ${{API_TOKEN}}" \\
  -H "Content-Type: application/json" \\
  -d '{{
    "name": "AdGuard DNS Block - Part {i}",
    "type": "HOSTNAME",
    "description": "AdGuard DNS filter domains - Part {i} of {num_lists}"
  }}' | jq -r '.result.id')

if [ -z "$LIST_ID_{i}" ] || [ "$LIST_ID_{i}" == "null" ]; then
  echo "${{RED}}Failed to create list {i}${{NC}}"
  exit 1
fi

echo "List {i} created with ID: $LIST_ID_{i}"

# Upload domains to the list
echo "Uploading domains to list {i}..."
while IFS= read -r domain; do
  DOMAINS_{i}+="{{\\\"value\\\":\\\"$domain\\\"}},"
done < adguard_domains_{i}.csv

# Remove trailing comma
DOMAINS_{i}=${{DOMAINS_{i}%,}}

curl -s -X POST "https://api.cloudflare.com/client/v4/accounts/${{ACCOUNT_ID}}/gateway/lists/${{LIST_ID_{i}}}/items" \\
  -H "Authorization: Bearer ${{API_TOKEN}}" \\
  -H "Content-Type: application/json" \\
  -d "[[${{DOMAINS_{i}}}]]"

echo "${{GREEN}}List {i} uploaded successfully${{NC}}"
sleep 1
'''

    script_content += '''
echo ""
echo "${GREEN}All lists uploaded successfully!${NC}"
echo ""
echo "Next steps:"
echo "1. Go to Cloudflare Zero Trust Dashboard"
echo "2. Navigate to Gateway > Firewall Policies > DNS"
echo "3. Create a new policy with the condition:"
echo "   Domain is in list: AdGuard DNS Block - Part 1"
'''

    for i in range(2, num_lists + 1):
        script_content += f'''echo "   OR Domain is in list: AdGuard DNS Block - Part {i}"
'''

    script_content += '''echo "4. Set Action to: Block"
echo ""
echo "This will create a SINGLE rule that blocks all domains!"
'''

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(script_content)

    # Make script executable
    import os
    os.chmod(output_file, 0o755)

    return output_file

def main():
    """Main execution function."""
    # Use command line argument or default URL
    if len(sys.argv) > 1:
        input_source = sys.argv[1]
    else:
        print("Using default AdGuard DNS filter URL")
        input_source = DEFAULT_URL

    try:
        domains, ips = process_input(input_source)
        if not domains and not ips:
            raise Exception("No valid domains or IPs found in the input.")

        print(f"Processed {len(domains)} unique domains and {len(ips)} unique IPs")

    except Exception as e:
        print(f"An error occurred while processing the input: {e}")
        sys.exit(1)

    # Split domains and IPs into lists
    domain_lists = split_into_lists(domains, MAX_DOMAINS_PER_LIST) if domains else []
    ip_lists = split_into_lists(ips, MAX_DOMAINS_PER_LIST) if ips else []
    num_domain_lists = len(domain_lists)
    num_ip_lists = len(ip_lists)

    print(f"Split into {num_domain_lists} domain lists and {num_ip_lists} IP lists")
    print(f"  (max {MAX_DOMAINS_PER_LIST} entries per list)")
    print("")

    # Write CSV files
    csv_files = []
    if domain_lists:
        print("Creating domain CSV files for Cloudflare import...")
        csv_files.extend(write_csv_lists(domain_lists, output_prefix="adguard_domains"))
        print("")

    if ip_lists:
        print("Creating IP CSV files for Cloudflare import...")
        csv_files.extend(write_csv_lists(ip_lists, output_prefix="adguard_ips"))
        print("")

    # Generate API upload script
    print("Generating API upload script...")
    script_file = "upload_lists.sh"
    # Note: This script generation is simplified - just output summary
    print(f"  - Note: Domains and IPs are now separated into different CSV files")
    print("")

    print("=" * 60)
    print("SUCCESS! Files created:")
    print("=" * 60)
    if num_domain_lists > 0:
        print(f"  {num_domain_lists} Domain CSV files: lists/adguard_domains_1.csv to lists/adguard_domains_{num_domain_lists}.csv")
    if num_ip_lists > 0:
        print(f"  {num_ip_lists} IP CSV files: lists/adguard_ips_1.csv to lists/adguard_ips_{num_ip_lists}.csv")
    print("")
    print("NEXT STEPS:")
    print("=" * 60)
    print("Manual Upload (recommended due to separate list types):")
    print("  1. Go to My Team > Lists in Cloudflare Zero Trust")
    print("  2. Upload domain CSV files:")
    print("     - Click 'Upload CSV'")
    print("     - Select List type: Hostname")
    print(f"     - Upload lists/adguard_domains_*.csv files ({num_domain_lists} files)")
    if num_ip_lists > 0:
        print("  3. Upload IP CSV files:")
        print("     - Click 'Upload CSV'")
        print("     - Select List type: IP")
        print(f"     - Upload lists/adguard_ips_*.csv files ({num_ip_lists} files)")
    print("  4. Create a DNS policy referencing all lists (both domains and IPs)")
    print("")
    print("This approach creates ONE RULE in Cloudflare!")
    print("=" * 60)

if __name__ == "__main__":
    main()
