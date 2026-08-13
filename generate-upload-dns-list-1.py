#!/usr/bin/env python3
"""
AdGuard DNS Filter to Cloudflare Gateway — Combined Script

This script:
1. Downloads the AdGuard DNS filter list
2. Parses and deduplicates all domains and IPs
3. Deletes existing policy first, then existing lists (by prefix)
4. Creates Cloudflare Gateway Lists (DOMAIN + IP type)
5. Creates a single DNS Block policy referencing all lists
"""

import os
import sys
import re
import time
import glob
import csv
import argparse
import requests
import ipaddress

from typing import List, Dict, Tuple
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────

ACCOUNT_ID = os.getenv("CLOUDFLARE_ACCOUNT_ID")
API_TOKEN  = os.getenv("CLOUDFLARE_API_TOKEN")

BASE_URL = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}"
HEADERS  = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type":  "application/json",
}

MAX_DOMAINS_PER_LIST = 1000  # Change to 5000 for Enterprise plans
RATE_LIMIT_DELAY     = 1     # seconds between API calls

POLICY_NAME      = "AdGuard DNS Filter"
LIST_NAME_PREFIX = "AdGuard"   # used for both "AdGuard Domains" and "AdGuard IPs"

DEFAULT_URL = (
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/refs/heads/master/filters/filter_15_DnsFilter/filter.txt"
)


# ─────────────────────────────────────────────
# Config check
# ─────────────────────────────────────────────

def check_config():
    if not ACCOUNT_ID or not API_TOKEN:
        print("❌ ERROR: Missing Cloudflare credentials")
        print("   Set CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN in .env")
        sys.exit(1)
    if ACCOUNT_ID == "your-account-id-here" or API_TOKEN == "your-api-token-here":
        print("❌ ERROR: Please replace placeholder values in .env")
        sys.exit(1)


# ─────────────────────────────────────────────
# Parsing
# ─────────────────────────────────────────────

def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_valid_domain(value: str) -> bool:
    if not value or "." not in value or "*" in value:
        return False
    if is_valid_ip(value):
        return False
    pattern = re.compile(
        r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
        r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    )
    return bool(pattern.match(value))


def parse_adguard_entry(line: str) -> Tuple[str, str]:
    """
    Parse one line from an AdGuard DNS filter list.
    Returns (type, value) where type is 'domain', 'ip', or None.
    """
    line = line.strip()
    if not line or line.startswith("!") or line.startswith("#"):
        return None, None

    if line.startswith("||") and "^" in line:
        value = line[2:].split("^")[0]
        if "/" in value or "$" in line or "*" in value:
            return None, None
        if is_valid_ip(value):
            return "ip", value
        if is_valid_domain(value):
            return "domain", value

    return None, None


def fetch_filter_list(source: str) -> Tuple[List[str], List[str]]:
    """Download or read filter list; return (domains, ips)."""
    if source.startswith("http://") or source.startswith("https://"):
        print(f"  Fetching filter list from: {source}")
        resp = requests.get(source, timeout=30)
        resp.raise_for_status()
        lines = resp.text.splitlines()
        print(f"  Downloaded {len(lines)} lines")
    else:
        print(f"  Reading from local file: {source}")
        with open(source, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
        print(f"  Read {len(lines)} lines")

    domains, ips = [], []
    for line in lines:
        entry_type, value = parse_adguard_entry(line)
        if entry_type == "domain":
            domains.append(value)
        elif entry_type == "ip":
            ips.append(value)

    # Deduplicate, preserve order
    domains = list(dict.fromkeys(domains))
    ips     = list(dict.fromkeys(ips))
    return domains, ips


# ─────────────────────────────────────────────
# CSV helpers
# ─────────────────────────────────────────────

def split_into_chunks(items: List[str], size: int) -> List[List[str]]:
    return [items[i:i + size] for i in range(0, len(items), size)]


def write_csv_files(chunks: List[List[str]], prefix: str) -> List[str]:
    os.makedirs("lists", exist_ok=True)
    files = []
    for idx, chunk in enumerate(chunks, 1):
        path = f"lists/{prefix}_{idx}.csv"
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            for item in chunk:
                writer.writerow([item])
        files.append(path)
        print(f"  - {path}: {len(chunk)} entries")
    return files


def read_csv_file(filepath: str) -> List[str]:
    with open(filepath, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


# ─────────────────────────────────────────────
# Cloudflare API helpers
# ─────────────────────────────────────────────

def get_existing_lists() -> Dict[str, str]:
    """Return {name: id} for all existing Gateway Lists."""
    resp = requests.get(f"{BASE_URL}/gateway/lists", headers=HEADERS)
    if resp.status_code == 200:
        return {item["name"]: item["id"] for item in resp.json()["result"]}
    return {}


def get_existing_rules() -> List[Dict]:
    """Return all existing Gateway Rules."""
    resp = requests.get(f"{BASE_URL}/gateway/rules", headers=HEADERS)
    if resp.status_code == 200:
        return resp.json().get("result", [])
    return []


def delete_rule_by_name(name: str):
    """Delete a Gateway Rule matching the given name."""
    rules = get_existing_rules()
    for rule in rules:
        if rule["name"] == name:
            rule_id = rule["id"]
            resp = requests.delete(f"{BASE_URL}/gateway/rules/{rule_id}", headers=HEADERS)
            if resp.status_code == 200:
                print(f"  ✅ Deleted policy: {name}")
            else:
                print(f"  ❌ Failed to delete policy: {name}")
                print(f"     Status: {resp.status_code}")
                print(f"     Body:   {resp.text}")
                sys.exit(1)
            return
    print(f"  ℹ️  No existing policy named '{name}' found — skipping")


def delete_lists_by_prefix(prefix: str):
    """Delete all Gateway Lists whose name starts with prefix."""
    existing = get_existing_lists()
    targets  = {n: lid for n, lid in existing.items() if n.startswith(prefix)}

    if not targets:
        print("  ℹ️  No existing lists to delete")
        return

    print(f"  Found {len(targets)} existing list(s) to delete")
    for name, lid in targets.items():
        resp = requests.delete(f"{BASE_URL}/gateway/lists/{lid}", headers=HEADERS)
        if resp.status_code == 200:
            print(f"  ✅ Deleted list: {name}")
        else:
            print(f"  ❌ Failed to delete list: {name}")
            print(f"     Status: {resp.status_code}")
            print(f"     Body:   {resp.text}")
            sys.exit(1)
        time.sleep(RATE_LIMIT_DELAY)


def create_gateway_list(name: str, list_type: str, description: str) -> str:
    """Create a Gateway List and return its ID."""
    data = {"name": name, "type": list_type, "description": description}
    resp = requests.post(f"{BASE_URL}/gateway/lists", headers=HEADERS, json=data)
    if resp.status_code == 200:
        list_id = resp.json()["result"]["id"]
        print(f"  ✅ Created list: {name} (ID: {list_id})")
        return list_id
    else:
        print(f"  ❌ Failed to create list: {name}")
        print(f"     Status: {resp.status_code}")
        print(f"     Body:   {resp.text}")
        sys.exit(1)


def upload_items_to_list(list_id: str, items: List[str], list_name: str):
    """PATCH items into an existing Gateway List."""
    payload = {"append": [{"value": item} for item in items]}
    resp    = requests.patch(f"{BASE_URL}/gateway/lists/{list_id}", headers=HEADERS, json=payload)
    if resp.status_code == 200:
        print(f"     ✅ Uploaded {len(items)} entries to {list_name}")
    else:
        print(f"     ❌ Failed to upload to {list_name}")
        print(f"        Status: {resp.status_code}")
        print(f"        Body:   {resp.text}")
        sys.exit(1)


def create_dns_block_policy(list_ids: List[str], domain_list_count: int, policy_name: str):
    """
    Create a Gateway DNS Block policy referencing all list IDs.

    Domain lists  → any(dns.domains[*] in $list_id)
    IP lists      → any(dns.resolved_ips[*] in $list_id)
    Combined with OR.
    """
    conditions = []
    for i, lid in enumerate(list_ids):
        if i < domain_list_count:
            conditions.append(f"any(dns.domains[*] in ${lid})")
        else:
            conditions.append(f"any(dns.resolved_ips[*] in ${lid})")

    traffic = " or ".join(conditions)

    data = {
        "name":        policy_name,
        "description": "Block domains and IPs from AdGuard DNS Filter",
        "enabled":     True,
        "action":      "block",
        "filters":     ["dns"],
        "traffic":     traffic,
        "rule_settings": {"block_page_enabled": False},
    }

    resp = requests.post(f"{BASE_URL}/gateway/rules", headers=HEADERS, json=data)
    if resp.status_code == 200:
        rule_id = resp.json()["result"]["id"]
        print(f"\n🎉 SUCCESS! Created DNS policy: {policy_name}")
        print(f"   Policy ID:        {rule_id}")
        print(f"   Lists referenced: {len(list_ids)}")
        return rule_id
    else:
        print(f"\n❌ Failed to create DNS policy")
        print(f"   Status: {resp.status_code}")
        print(f"   Body:   {resp.text}")
        sys.exit(1)


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Upload AdGuard DNS Filter to Cloudflare Zero Trust Gateway"
    )
    parser.add_argument(
        "source", nargs="?", default=DEFAULT_URL,
        help="URL or local path to AdGuard filter list (default: AdGuard DNS filter)"
    )
    parser.add_argument("-y", "--auto-approve", action="store_true",
                        help="Skip confirmation prompts (for CI/CD)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Parse & write CSVs only, no Cloudflare API calls")
    args = parser.parse_args()

    print("=" * 70)
    print("Cloudflare Zero Trust — AdGuard DNS Filter Upload")
    print("=" * 70)
    if args.auto_approve:
        print("Running in AUTO-APPROVE mode")
    if args.dry_run:
        print("DRY RUN mode — no API calls will be made")
    print()

    check_config()

    # ── Step 0: Download & parse ──────────────────────────────────────────
    print("=" * 70)
    print("Step 0: Fetching AdGuard DNS filter list")
    print("=" * 70)
    domains, ips = fetch_filter_list(args.source)
    print(f"\n  Unique domains : {len(domains)}")
    print(f"  Unique IPs     : {len(ips)}")
    print()

    if not domains and not ips:
        print("❌ No valid entries found. Aborting.")
        sys.exit(1)

    # ── Step 1: Write CSVs ───────────────────────────────────────────────
    print("=" * 70)
    print("Step 1: Writing CSV files")
    print("=" * 70)

    domain_chunks = split_into_chunks(domains, MAX_DOMAINS_PER_LIST)
    ip_chunks     = split_into_chunks(ips,     MAX_DOMAINS_PER_LIST)

    domain_files = write_csv_files(domain_chunks, prefix="adguard_domains")
    ip_files     = write_csv_files(ip_chunks,     prefix="adguard_ips")

    print(f"\n  {len(domain_files)} domain file(s), {len(ip_files)} IP file(s) written")
    print()

    if args.dry_run:
        print("DRY RUN: stopping before API calls.")
        return 0

    # ── Confirm ──────────────────────────────────────────────────────────
    total_lists = len(domain_files) + len(ip_files)
    print("This will:")
    print(f"  - Delete existing '{POLICY_NAME}' policy")
    print(f"  - Delete existing '{LIST_NAME_PREFIX}' lists")
    print(f"  - Create {total_lists} list(s) in Cloudflare")
    print(f"  - Create 1 DNS Block policy: '{POLICY_NAME}'")
    print()

    if not args.auto_approve:
        ans = input("Continue? (yes/no): ").strip().lower()
        if ans not in ("yes", "y"):
            print("Cancelled.")
            sys.exit(0)

    # ── Step 2: Clean up — policy first, then lists ──────────────────────
    print()
    print("=" * 70)
    print("Step 2: Removing existing policy & lists")
    print("=" * 70)
    delete_rule_by_name(POLICY_NAME)
    time.sleep(2)
    delete_lists_by_prefix(LIST_NAME_PREFIX)
    print()

    # ── Step 3: Create lists and upload entries ───────────────────────────
    print("=" * 70)
    print("Step 3: Creating lists and uploading entries")
    print("=" * 70)

    list_ids          = []
    domain_list_count = len(domain_files)

    # Domain lists
    for i, filepath in enumerate(domain_files, 1):
        list_name = f"AdGuard Domains - Part {i}"
        print(f"\n[{i}/{len(domain_files)}] {list_name}")
        items   = read_csv_file(filepath)
        list_id = create_gateway_list(
            name=list_name,
            list_type="DOMAIN",
            description=f"AdGuard DNS Filter domains — Part {i} of {len(domain_files)}",
        )
        list_ids.append(list_id)
        upload_items_to_list(list_id, items, list_name)
        time.sleep(RATE_LIMIT_DELAY)

    # IP lists
    if ip_files:
        print()
        for i, filepath in enumerate(ip_files, 1):
            list_name = f"AdGuard IPs - Part {i}"
            print(f"\n[{i}/{len(ip_files)}] {list_name}")
            items   = read_csv_file(filepath)
            list_id = create_gateway_list(
                name=list_name,
                list_type="IP",
                description=f"AdGuard DNS Filter IPs — Part {i} of {len(ip_files)}",
            )
            list_ids.append(list_id)
            upload_items_to_list(list_id, items, list_name)
            time.sleep(RATE_LIMIT_DELAY)

    # ── Step 4: Create DNS Block policy ──────────────────────────────────
    print()
    print("=" * 70)
    print("Step 4: Creating DNS Block policy")
    print("=" * 70)
    create_dns_block_policy(list_ids, domain_list_count, POLICY_NAME)

    # ── Summary ───────────────────────────────────────────────────────────
    print()
    print("=" * 70)
    print("🎉 ALL DONE!")
    print("=" * 70)
    print(f"✅ {len(domain_files)} domain list(s) created")
    print(f"✅ {len(ip_files)} IP list(s) created")
    print(f"✅ DNS policy created: '{POLICY_NAME}'")
    print()
    print("Next steps:")
    print("  1. Cloudflare Zero Trust Dashboard")
    print("  2. Gateway → Firewall Policies → DNS")
    print(f"  3. Verify policy '{POLICY_NAME}' is enabled")
    print()
    print("=" * 70)

    return 0


if __name__ == "__main__":
    sys.exit(main())
