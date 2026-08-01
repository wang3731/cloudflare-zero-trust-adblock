import requests
import os
from dotenv import load_dotenv

load_dotenv()

ACCOUNT_ID = os.environ["CLOUDFLARE_ACCOUNT_ID"]
API_TOKEN  = os.environ["CLOUDFLARE_API_TOKEN"]
BASE_URL   = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/gateway"

HEADERS = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type": "application/json"
}

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

def fetch_domains():
    domains = set()
    for url in EXCLUSION_SOURCES:
        print(f"下載 {url.split('/')[-1]}...")
        r = requests.get(url)
        for line in r.text.splitlines():
            line = line.strip()
            # 跳過空行、註解、app 限定規則
            if not line or line.startswith('//') or line.startswith('#'):
                continue
            if '$app=' in line:
                continue
            # 去掉引號（exact match 語法）
            line = line.strip('"')
            domains.add(line)
    print(f"共 {len(domains)} 個 domain")
    return sorted(domains)

def delete_existing_policy(name):
    r = requests.get(f"{BASE_URL}/rules", headers=HEADERS)
    for rule in r.json().get("result", []):
        if rule["name"] == name:
            rid = rule["id"]
            del_r = requests.delete(f"{BASE_URL}/rules/{rid}", headers=HEADERS)
            if del_r.status_code == 200:
                print(f"刪除舊 policy: {name}")
            else:
                print(f"❌ 刪除 policy 失敗: {name} ({del_r.status_code}) {del_r.text}")

def delete_existing_list(name):
    r = requests.get(f"{BASE_URL}/lists", headers=HEADERS)
    for lst in r.json().get("result", []):
        if lst["name"] == name:
            del_r = requests.delete(f"{BASE_URL}/lists/{lst['id']}", headers=HEADERS)
            if del_r.status_code == 200:
                print(f"刪除舊 list: {name}")
            else:
                print(f"❌ 刪除 list 失敗: {name} ({del_r.status_code}) {del_r.text}")

def upload_list(domains):
    LIST_NAME = "AdGuard HTTPS Exclusions"
    delete_existing_list(LIST_NAME)

    # Cloudflare 每個 list 最多 1000 筆，切分上傳
    list_ids = []
    chunks = [domains[i:i+1000] for i in range(0, len(domains), 1000)]

    for i, chunk in enumerate(chunks, 1):
        name = f"{LIST_NAME} {i}"
        delete_existing_list(name)
        print(f"上傳 {name} ({len(chunk)} 筆)...")
        r = requests.post(
            f"{BASE_URL}/lists",
            headers=HEADERS,
            json={
                "name": name,
                "type": "DOMAIN",
                "items": [{"value": d} for d in chunk]
            }
        )
        data = r.json()
        if data.get("success"):
            list_ids.append(data["result"]["id"])
            print(f"  ✅ 成功")
        else:
            print(f"  ❌ 失敗: {data['errors']}")

    return list_ids

def create_noinspect_policy(list_ids):
    POLICY_NAME = "AdGuard HTTPS No Inspect"
    delete_existing_policy(POLICY_NAME)

    traffic = " or ".join(
        [f"any(http.request.domains[*] in ${lid})" for lid in list_ids]
    )

    print("建立 No Inspect policy...")
    r = requests.post(
        f"{BASE_URL}/rules",
        headers=HEADERS,
        json={
            "name": POLICY_NAME,
            "description": "Do not inspect AdGuard HTTPS exclusions (banks, sensitive, issues)",
            "action": "off",        # ← No Inspect
            "filters": ["http"],
            "traffic": traffic,
            "enabled": True,
            "precedence": 0         # ← 放最高優先
        }
    )
    data = r.json()
    if data.get("success"):
        print("✅ No Inspect policy 建立成功！")
    else:
        print(f"❌ 失敗: {data['errors']}")

if __name__ == "__main__":
    LIST_NAME = "AdGuard HTTPS Exclusions"
    POLICY_NAME = "AdGuard HTTPS No Inspect"

    # Delete the policy FIRST — Cloudflare refuses to delete a list while
    # any rule (even disabled) still references it. The old code deleted
    # the policy last, inside create_noinspect_policy(), by which point
    # delete_existing_list() had already failed on every list.
    # delete_existing_policy(POLICY_NAME)

    domains = fetch_domains()
    list_ids = upload_list(domains)
    if list_ids:
        create_noinspect_policy(list_ids)
