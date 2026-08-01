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
    domains_domain = set()
    domains_ip = set()
    for url in EXCLUSION_SOURCES:
        print(f"下載 {url.split('/')[-1]}...")
        try:
            r = requests.get(url, timeout=15)
            r.raise_for_status()
        except Exception as e:
            print(f"  ⚠️ 下載失敗，略過: {e}")
            continue
        for line in r.text.splitlines():
            line = line.strip().strip('"')
            if not line or line.startswith('//') or line.startswith('#'):
                continue
            if '$app=' in line:
                continue
            # 區分 IP 和 domain
            try:
                import ipaddress
                ipaddress.ip_address(line)
                domains_ip.add(line)
            except ValueError:
                domains_domain.add(line)

    print(f"共 {len(domains_domain)} 個 domain，{len(domains_ip)} 個 IP")
    return sorted(domains_domain), sorted(domains_ip)

def delete_existing_policy(name):
    r = requests.get(f"{BASE_URL}/rules", headers=HEADERS)
    for rule in r.json().get("result", []):
        if rule["name"] == name:
            rid = rule["id"]
            requests.delete(f"{BASE_URL}/rules/{rid}", headers=HEADERS)
            print(f"刪除舊 policy: {name}")

def delete_existing_list(name):
    r = requests.get(f"{BASE_URL}/lists", headers=HEADERS)
    for lst in r.json().get("result", []):
        if lst["name"] == name:
            requests.delete(f"{BASE_URL}/lists/{lst['id']}", headers=HEADERS)
            print(f"刪除舊 list: {name}")

def upload_list(domains, list_type, base_name):
    """通用上傳函數，domain/IP 分開呼叫"""
    list_ids = []
    chunks = [domains[i:i+1000] for i in range(0, len(domains), 1000)]

    for i, chunk in enumerate(chunks, 1):
        name = f"{base_name} {i}"
        delete_existing_list(name)
        print(f"上傳 {name} ({len(chunk)} 筆)...")
        r = requests.post(
            f"{BASE_URL}/lists",
            headers=HEADERS,
            json={"name": name, "type": list_type,
                  "items": [{"value": d} for d in chunk]}
        )
        data = r.json()
        if data.get("success"):
            list_ids.append(data["result"]["id"])
            print("  ✅ 成功")
        else:
            print(f"  ❌ 失敗: {data['errors']}")
    return list_ids

def create_noinspect_policy(list_ids):
    POLICY_NAME = "AdGuard HTTPS No Inspect"
    delete_existing_policy(POLICY_NAME)

    traffic = " or ".join(
        [f"any(http.conn.domains[*] in ${lid})" for lid in list_ids]
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
    domains, ips = fetch_domains()
    list_ids = []
    if domains:
        list_ids += upload_list(domains, "DOMAIN", "AdGuard HTTPS Exclusions")
    if ips:
        list_ids += upload_list(ips, "IP", "AdGuard HTTPS Exclusions IP")
    if list_ids:
        create_noinspect_policy(list_ids)
