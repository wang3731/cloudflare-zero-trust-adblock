#!/usr/bin/env python3
"""
AdGuard DNS Filter to Cloudflare Zero Trust Regex Converter

This script downloads the AdGuard DNS filter list and converts it to
regex patterns compatible with Cloudflare Zero Trust DNS firewall policies.
"""

import sys
import re
import requests

# Cloudflare DNS rule limiting
MAX_CHARS = 6500

# Default AdGuard DNS filter URL
DEFAULT_URL = "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/refs/heads/master/filters/filter_15_DnsFilter/filter.txt"

def parse_adguard_domain(line):
    """
    Parse AdGuard filter format and extract domain pattern.
    AdGuard format: ||domain.com^ or ||subdomain.domain.com^
    Returns the domain pattern suitable for regex matching.
    """
    line = line.strip()

    # Skip empty lines and comments
    if not line or line.startswith("!") or line.startswith("#"):
        return None

    # Extract domain from AdGuard format ||domain^
    if line.startswith("||") and "^" in line:
        # Remove || prefix and everything after ^
        domain = line[2:].split("^")[0]

        # Skip if it contains path separators or complex rules
        if "/" in domain or "$" in line:
            return None

        # Escape dots for regex
        domain = domain.replace(".", r"\.")

        # Handle wildcards - AdGuard uses * for wildcards
        domain = domain.replace("*", ".*")

        return domain

    return None

def process_input(input_source):
    """Process AdGuard filter list from URL or local file."""
    rules = []

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
        domain_pattern = parse_adguard_domain(line)
        if domain_pattern:
            rules.append(domain_pattern)

    # Remove duplicates while preserving order
    rules = list(dict.fromkeys(rules))

    return rules

def group_rules(rules, max_length):
    """Group rules into chunks that fit within Cloudflare's character limit."""
    groups = []
    current_group = ""
    allowed_length = max_length - 2  # Account for wrapping parentheses

    for rule in rules:
        if not current_group:
            candidate = rule
        else:
            candidate = current_group + "|" + rule

        if len(candidate) <= allowed_length:
            current_group = candidate
        else:
            # Finish the current group and start a new one
            groups.append(current_group)
            current_group = rule

    if current_group:
        groups.append(current_group)

    return groups

def main():
    """Main execution function."""
    # Use command line argument or default URL
    if len(sys.argv) > 1:
        input_source = sys.argv[1]
    else:
        print("Using default AdGuard DNS filter URL")
        input_source = DEFAULT_URL

    try:
        rules = process_input(input_source)
        if not rules:
            raise Exception("No valid domain rules found in the input.")

        print(f"Processed {len(rules)} unique domain patterns")

    except Exception as e:
        print(f"An error occurred while processing the input: {e}")
        sys.exit(1)

    # Group rules by character limit
    groups = group_rules(rules, MAX_CHARS)
    print(f"Created {len(groups)} regex groups (Cloudflare limit: {MAX_CHARS} chars per rule)")

    # Write output files
    output_files = []
    for idx, group in enumerate(groups):
        regex = "(" + group + ")"

        if len(groups) == 1:
            file_name = "blocklist.txt"
        else:
            file_name = f"blocklist_{idx+1}.txt"

        with open(file_name, 'w', encoding='utf-8') as f:
            f.write(regex)

        output_files.append(file_name)
        print(f"  - {file_name}: {len(regex)} characters")

    print("\nRegex patterns successfully written to the following file(s):")
    for f in output_files:
        print(f"  {f}")

    print("\nYou can now copy these regex patterns into your Cloudflare Zero Trust DNS firewall policy.")

if __name__ == "__main__":
    main()
