#!/usr/bin/env python3
"""
AdGuard HTTPS Exclusions to Cloudflare Gateway HTTP Policy Converter

This script:
1. Downloads AdGuard HTTPS exclusion lists (banks, sensitive, issues, platform-specific)
2. Parses and deduplicates all domains
3. Creates Cloudflare Gateway Lists (DOMAIN type)
4. Creates a single HTTP "Do Not Inspect" policy referencing all lists
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

# Configuration
ACCOUNT_ID = os.getenv("CLOUDFLARE_ACCOUNT_ID")
API_TOKEN  = os.getenv("CLOUDFLARE_API_TOKEN")

BASE_URL = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}"
HEADERS  = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type":  "application/json",
}

# Cloudflare Gateway List limits
MAX_DOMAINS_PER_LIST = 1000

# Rate limiting
RATE_LIMIT_DELAY = 1  # seconds between API calls

# Policy name — used to identify & clean up on re-run
POLICY_NAME = "AdGuard HTTPS No Inspect"

# AdGuard 官方 HTTPS 排除清單
EXCLUSION_SOURCES = [
    "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/banks.txt",
    "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/sensitive.txt",
    "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/issues.txt",
    "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/android.txt",
    "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/mac.txt",
    "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/windows.txt",
    "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/firefox.txt",
]

LIST_NAME_PREFIX = "AdGuard_No_Inspect"


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
# Domain parsing
# ─────────────────────────────────────────────

import ipaddress

def is_valid_domain(value: str) -> bool:
    if not value or "." not in value or "*" in value:
        return False
    # 過濾掉 IP address
    try:
        ipaddress.ip_address(value)
        return False  # 是 IP，排除
    except ValueError:
        pass
    pattern = re.compile(
        r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
        r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    )
    return bool(pattern.match(value))


def parse_exclusion_line(line: str):
    """
    Parse one line from an AdGuard HTTPS exclusion file.
    Formats seen:
      example.com
      ||example.com^
      # comment
      ! comment
    Returns a clean domain string or None.
    """
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("!"):
        return None

    # AdGuard filter syntax
    if line.startswith("||") and "^" in line:
        line = line[2:].split("^")[0]

    # Strip leading dots or slashes
    line = line.lstrip("./")

    # Remove port numbers
    line = line.split(":")[0]

    return line if is_valid_domain(line) else None


def fetch_exclusions(sources: List[str]) -> List[str]:
    """Download all exclusion sources and return a deduplicated domain list."""
    all_domains = []

    for url in sources:
        source_name = url.split("/")[-1]
        print(f"  Fetching {source_name}...")
        try:
            resp = requests.get(url, timeout=30)
            resp.raise_for_status()
            lines = resp.text.splitlines()
            parsed = [parse_exclusion_line(l) for l in lines]
            valid  = [d for d in parsed if d]
            print(f"    → {len(valid)} domains")
            all_domains.extend(valid)
        except Exception as e:
            print(f"  ⚠️  Failed to fetch {url}: {e}")

    # Deduplicate, preserve order
    unique = list(dict.fromkeys(all_domains))
    return unique


# ─────────────────────────────────────────────
# CSV helpers
# ─────────────────────────────────────────────

def split_into_chunks(items: List[str], size: int) -> List[List[str]]:
    return [items[i:i + size] for i in range(0, len(items), size)]


def write_csv_files(domain_chunks: List[List[str]], prefix: str = "adguard_noinspect") -> List[str]:
    os.makedirs("lists", exist_ok=True)
    files = []
    for idx, chunk in enumerate(domain_chunks, 1):
        path = f"lists/{prefix}_{idx}.csv"
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            for domain in chunk:
                writer.writerow([domain])
        files.append(path)
        print(f"  - {path}: {len(chunk)} domains")
    return files


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
    print(f"  ℹ️  No existing policy named '{name}' found — skipping delete")


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


def create_gateway_list(name: str, description: str) -> str:
    """Create a DOMAIN-type Gateway List and return its ID."""
    data = {"name": name, "type": "DOMAIN", "description": description}
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
        print(f"     ✅ Uploaded {len(items)} domains to {list_name}")
    else:
        print(f"     ❌ Failed to upload to {list_name}")
        print(f"        Status: {resp.status_code}")
        print(f"        Body:   {resp.text}")
        sys.exit(1)


def create_http_noinspect_policy(list_ids: List[str], policy_name: str):
    """
    Create a Gateway HTTP 'Do Not Inspect' policy referencing all list IDs.

    API action value for Do Not Inspect = "off"
    Selector: any(http.request.domains[*] in $list_id)
    Combined with OR.
    """
    conditions = [f"any(http.conn.domains[*] in ${lid})" for lid in list_ids]
    traffic    = " or ".join(conditions)

    data = {
        "name":        policy_name,
        "description": "Bypass HTTPS inspection for AdGuard exclusion domains",
        "enabled":     True,
        "action":      "off",          # Do Not Inspect
        "filters":     ["http"],       # HTTP policy
        "traffic":     traffic,
        "rule_settings": {},
    }

    resp = requests.post(f"{BASE_URL}/gateway/rules", headers=HEADERS, json=data)
    if resp.status_code == 200:
        rule_id = resp.json()["result"]["id"]
        print(f"\n🎉 SUCCESS! Created HTTP policy: {policy_name}")
        print(f"   Policy ID: {rule_id}")
        print(f"   Lists referenced: {len(list_ids)}")
        return rule_id
    else:
        print(f"\n❌ Failed to create HTTP policy")
        print(f"   Status: {resp.status_code}")
        print(f"   Body:   {resp.text}")
        sys.exit(1)


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Upload AdGuard HTTPS exclusions as a Cloudflare Gateway Do-Not-Inspect policy"
    )
    parser.add_argument("-y", "--auto-approve", action="store_true",
                        help="Skip confirmation prompts (for CI/CD)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Parse & write CSVs only, no Cloudflare API calls")
    args = parser.parse_args()

    print("=" * 70)
    print("Cloudflare Zero Trust - AdGuard HTTPS No-Inspect Policy")
    print("=" * 70)
    if args.auto_approve:
        print("Running in AUTO-APPROVE mode")
    if args.dry_run:
        print("DRY RUN mode — no API calls will be made")
    print()

    check_config()

    # ── Step 0: Download & parse exclusions ──────────────────────────────
    print("=" * 70)
    print("Step 0: Fetching AdGuard HTTPS exclusion lists")
    print("=" * 70)
    domains = fetch_exclusions(EXCLUSION_SOURCES)
    print(f"\nTotal unique domains: {len(domains)}")
    print()

    if not domains:
        print("❌ No domains found. Aborting.")
        sys.exit(1)

    # ── Step 1: Write CSVs ───────────────────────────────────────────────
    print("=" * 70)
    print("Step 1: Writing CSV files")
    print("=" * 70)
    chunks     = split_into_chunks(domains, MAX_DOMAINS_PER_LIST)
    csv_files  = write_csv_files(chunks, prefix="adguard_noinspect")
    print(f"\n{len(csv_files)} CSV file(s) written")
    print()

    if args.dry_run:
        print("DRY RUN: stopping before API calls.")
        return 0

    # ── Confirm ──────────────────────────────────────────────────────────
    print("This will:")
    print(f"  - Delete existing '{LIST_NAME_PREFIX}' lists and '{POLICY_NAME}' policy")
    print(f"  - Create {len(chunks)} DOMAIN list(s) in Cloudflare")
    print(f"  - Create 1 HTTP Do-Not-Inspect policy: '{POLICY_NAME}'")
    print()

    if not args.auto_approve:
        ans = input("Continue? (yes/no): ").strip().lower()
        if ans not in ("yes", "y"):
            print("Cancelled.")
            sys.exit(0)

    # ── Step 2: Clean up existing resources ──────────────────────────────
    print()
    print("=" * 70)
    print("Step 2: Removing existing policy & lists")
    print("=" * 70)
    delete_rule_by_name(POLICY_NAME)
    time.sleep(2)
    delete_lists_by_prefix(LIST_NAME_PREFIX)
    print()

    # ── Step 3: Create lists and upload domains ───────────────────────────
    print("=" * 70)
    print("Step 3: Creating lists and uploading domains")
    print("=" * 70)

    list_ids = []
    total    = len(chunks)

    for i, (chunk, csv_path) in enumerate(zip(chunks, csv_files), 1):
        list_name = f"{LIST_NAME_PREFIX} - Part {i}"
        print(f"\n[{i}/{total}] {list_name}")

        list_id = create_gateway_list(
            name=list_name,
            description=f"AdGuard HTTPS exclusions — Part {i} of {total}",
        )
        list_ids.append(list_id)

        upload_items_to_list(list_id, chunk, list_name)
        time.sleep(RATE_LIMIT_DELAY)

    # ── Step 4: Create HTTP Do-Not-Inspect policy ─────────────────────────
    print()
    print("=" * 70)
    print("Step 4: Creating HTTP Do-Not-Inspect policy")
    print("=" * 70)
    create_http_noinspect_policy(list_ids, POLICY_NAME)

    # ── Summary ───────────────────────────────────────────────────────────
    print()
    print("=" * 70)
    print("🎉 ALL DONE!")
    print("=" * 70)
    print(f"✅ {len(list_ids)} DOMAIN list(s) created")
    print(f"✅ HTTP policy created: '{POLICY_NAME}'")
    print()
    print("Next steps:")
    print("  1. Cloudflare Zero Trust Dashboard")
    print("  2. Gateway → Firewall Policies → HTTP")
    print(f"  3. Verify policy '{POLICY_NAME}' is enabled")
    print("  4. Do Not Inspect policies always evaluate first — no reordering needed")
    print()
    print("=" * 70)

    return 0


if __name__ == "__main__":
    sys.exit(main())
