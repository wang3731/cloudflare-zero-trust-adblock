#!/usr/bin/env python3
import os
import sys
import time
import requests
from dotenv import load_dotenv

load_dotenv()

ACCOUNT_ID = os.getenv("CLOUDFLARE_ACCOUNT_ID")
API_TOKEN = os.getenv("CLOUDFLARE_API_TOKEN")
BASE_URL = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}"
HEADERS = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type": "application/json"
}

def get_existing_lists() -> Dict[str, str]:
    """
    Get all existing Gateway Lists.
    Returns a dict mapping list names to list IDs.
    """
    url = f"{BASE_URL}/gateway/lists"
    response = requests.get(url, headers=HEADERS)

    if response.status_code == 200:
        lists = response.json()["result"]
        return {list_item["name"]: list_item["id"] for list_item in lists}
    else:
        return {}


def delete_existing_adguard_lists(auto_approve=False):
    """Delete any existing AdGuard lists to allow fresh upload."""
    print("Checking for existing AdGuard lists...")

    existing_lists = get_existing_lists()
    adguard_lists = {name: list_id for name, list_id in existing_lists.items()
                     if name.startswith("AdGuard")}

    if adguard_lists:
        print(f"Found {len(adguard_lists)} existing AdGuard lists")

        if auto_approve:
            response = 'yes'
            print("Auto-approving deletion (--auto-approve enabled)")
        else:
            response = input("Delete these lists before uploading? (yes/no): ").strip().lower()

        if response in ['yes', 'y']:
            for name, list_id in adguard_lists.items():
                url = f"{BASE_URL}/gateway/lists/{list_id}"
                del_response = requests.delete(url, headers=HEADERS)

                if del_response.status_code == 200:
                    print(f"  ✅ Deleted: {name}")
                else:
                    print(f"  ❌ Failed to delete: {name}")

            print()
        else:
            print("⚠️  Warning: Existing lists may cause conflicts")
            print()
def main():
    delete_existing_adguard_lists(auto_approve=False)
    print("\n完成")

if __name__ == "__main__":
    main()
