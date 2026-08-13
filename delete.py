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

def get_all_lists():
    resp = requests.get(f"{BASE_URL}/gateway/lists", headers=HEADERS)
    if resp.status_code != 200:
        print(f"❌ 無法取得 lists: {resp.text}")
        sys.exit(1)
    return resp.json()["result"]

def delete_list(list_id, name):
    resp = requests.delete(f"{BASE_URL}/gateway/lists/{list_id}", headers=HEADERS)
    if resp.status_code == 200:
        print(f"  ✅ 已刪除: {name}")
    else:
        print(f"  ❌ 刪除失敗: {name}")
        print(f"     {resp.text}")

def main():
    all_lists = get_all_lists()

    # 篩選要刪的（可改關鍵字）
    target = [l for l in all_lists if l["name"].startswith("AdGuard")]

    if not target:
        print("找不到符合條件的 lists")
        return

    print(f"找到 {len(target)} 個 lists：")
    for l in target:
        print(f"  - {l['name']} ({l['id']})")

    confirm = input("\n確定刪除？(yes/no): ").strip().lower()
    if confirm not in ["yes", "y"]:
        print("取消")
        return

    for l in target:
        delete_list(l["id"], l["name"])
        time.sleep(0.5)

    print("\n完成")

if __name__ == "__main__":
    main()
