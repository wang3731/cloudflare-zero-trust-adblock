# AdGuard DNS Filter to Cloudflare Zero Trust

Block ads, trackers, and malicious websites across your entire network using [AdGuard DNS Filter](https://github.com/AdguardTeam/FiltersRegistry) deployed to Cloudflare Zero Trust Gateway.

> **Warning:** This blocklist is comprehensive (144K+ domains) and may impact website functionality. Test in a controlled environment before deploying broadly.

## Features

- **144,452 domains + 66 IPs** from AdGuard DNS Filter
- **One-click deployment** via automated API upload
- **Single DNS policy** blocks all domains (not 499 separate rules!)
- Automatically separates domains from IP addresses
- Optimized for Cloudflare Standard plan (1,000 entries per list)
- Enterprise plan support (5,000 entries per list)
- Easy updates - just re-run the script

## Requirements

- Python 3.6+
- Cloudflare Zero Trust account (Free plan works!)
- API credentials (instructions below)

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

Or install manually:
```bash
pip install requests python-dotenv
```

### 2. Set Up Cloudflare Credentials

```bash
# Copy the template
cp .env.example .env

# Edit with your credentials
nano .env
```

Add your Cloudflare credentials:
```env
CLOUDFLARE_ACCOUNT_ID=your-account-id
CLOUDFLARE_API_TOKEN=your-api-token
```

**How to get credentials:**
- **Account ID:** Cloudflare Dashboard → Zero Trust → Settings
- **API Token:** Cloudflare Dashboard → My Profile → API Tokens
  - Click "Create Token"
  - Use "Edit Cloudflare Zero Trust" template

### 3. Generate the Lists

```bash
python3 generate-lists.py
```

This downloads the latest AdGuard DNS filter and creates:
- 145 domain CSV files (1,000 entries each)
- 1 IP CSV file (66 entries)
- All files saved to `lists/` folder

**Example output:**
```
Fetching filter list from: https://raw.githubusercontent.com/...
Downloaded 180237 lines
Processed 144452 unique domains and 66 unique IPs
Split into 145 domain lists and 1 IP lists
  (max 1000 entries per list)

Creating domain CSV files for Cloudflare import...
  - lists/adguard_domains_1.csv: 1000 domains
  - lists/adguard_domains_2.csv: 1000 domains
  ...
  - lists/adguard_domains_145.csv: 452 domains

Creating IP CSV files for Cloudflare import...
  - lists/adguard_ips_1.csv: 66 domains

SUCCESS! Files created
```

### 4. Upload to Cloudflare

**Option A: Automated Upload (Recommended)**

```bash
python3 upload_to_cloudflare.py
```

This automatically:
- Creates 146 Gateway Lists in Cloudflare
- Uploads all domains and IPs
- Creates a single DNS policy blocking everything
- Enables the policy

**Option B: Test First (Dry Run)**

```bash
# See what would be uploaded without making changes
python3 upload_to_cloudflare.py --dry-run
```

**Option C: Manual Upload**

If you prefer to upload manually, see [Manual Upload](#manual-upload-alternative) section below.

**Done!** Your network is now protected.

## Configuration

### Enterprise Plan (5,000 entries per list)

Edit `generate-lists.py` line 20:

```python
MAX_DOMAINS_PER_LIST = 5000
```

This reduces the number of lists from 145 to ~30.

### Custom Filter Source

Use any AdGuard-formatted filter:

```bash
python3 generate-lists.py https://example.com/custom-filter.txt
```

## Updating the Filter

### Manual Update

To get the latest AdGuard DNS filter:

```bash
# Regenerate lists
python3 generate-lists.py

# Re-upload to Cloudflare (interactive)
python3 upload_to_cloudflare.py
```

The script will offer to delete existing lists before uploading new ones.

### Automated Updates (Optional)

For automatic updates via cron job, use the `--auto-approve` flag:

```bash
# Non-interactive mode (skips all prompts)
python3 upload_to_cloudflare.py --auto-approve
```

**Example cron job** (updates weekly on Sunday at 2 AM):

```bash
# Edit crontab
crontab -e

# Add this line (adjust paths to match your system):
0 2 * * 0 cd /path/to/cfzt-adblock-dns-firewall && /usr/bin/python3 generate-lists.py && /usr/bin/python3 upload_to_cloudflare.py --auto-approve >> /var/log/adguard-update.log 2>&1
```

**Find your python3 path:**
```bash
which python3
# Use this full path in your cron job
```

This automatically:
- Downloads the latest AdGuard filter
- Generates fresh CSV files
- Deletes old Cloudflare lists
- Uploads new lists
- Updates the DNS policy

## Manual Upload (Alternative)

If you prefer manual upload over API:

### 1. Upload Domain Lists

1. Go to **My Team** → **Lists** in Cloudflare Zero Trust
2. Click **Upload CSV**
3. Select **List type: Hostname**
4. Upload each `lists/adguard_domains_*.csv` file
5. Name them: "AdGuard Domains - Part 1", "Part 2", etc.

### 2. Upload IP List

1. Click **Upload CSV**
2. Select **List type: IP**
3. Upload `lists/adguard_ips_1.csv`
4. Name it: "AdGuard IPs"

### 3. Create DNS Policy

1. Go to **Gateway** → **Firewall Policies** → **DNS**
2. Click **Add a policy**
3. Configure:
   - **Name:** "Block AdGuard DNS Filter"
   - **Traffic:** Add all lists with OR conditions
   - **Action:** Block
4. Save

## Troubleshooting

### Installation Issues

**"No module named 'requests'"**
```bash
pip install -r requirements.txt
```

**"python3: command not found"**

Use `python` instead of `python3`, or install Python 3.6+.

### Configuration Issues

**"No CSV files found"**

Run `python3 generate-lists.py` first to create the lists.

**"Missing Cloudflare credentials"**

Create a `.env` file with your credentials:
```bash
cp .env.example .env
nano .env  # Add your actual credentials
```

### API Errors

**"invalid list type"**

The API type should be `DOMAIN` for domains and `IP` for IPs. The script handles this automatically.

**"list has type IP but should have type Host"**

You're using `dns.domains[*]` with an IP list. Use `dns.resolved_ips[*]` instead. The upload script handles this correctly.

**"cannot have list with over 1000 items"**

You're on a Standard plan. Keep `MAX_DOMAINS_PER_LIST = 1000` (default).

**"A resource with this identifier already exists"**

You have existing lists. The script will prompt to delete them, or use:
```bash
python3 upload_to_cloudflare.py --auto-approve
```

## How It Works

### Architecture

1. **Gateway Lists** (146 total):
   - 145 domain lists (type: `DOMAIN`)
   - 1 IP list (type: `IP`)
   - Max 1,000 entries per list (Standard plan)

2. **Single DNS Policy**:
   - Combines all 146 lists with OR conditions
   - Domain lists: `any(dns.domains[*] in $list_id)`
   - IP lists: `any(dns.resolved_ips[*] in $list_id)`
   - Action: Block

### Why Gateway Lists?

| Approach | Rules Needed | Maintenance | Recommended |
|----------|-------------|-------------|-------------|
| **Gateway Lists** | 1 policy | Easy | ✅ Yes |
| Regex patterns | 499 policies | Hard | ❌ No |

### Alternative: Regex Method

For those who prefer regex patterns over Gateway Lists:

```bash
python3 domain-lists-dc.py
```

This generates 499 regex files (`blocklist_*.txt`) with 6,500 character limit each. You'll need to create 499 separate DNS policies in Cloudflare.

**Note:** Gateway Lists method is strongly recommended over regex.

## Files in This Repository

```
.
├── generate-lists.py           # Main script: generates CSV files
├── upload_to_cloudflare.py     # Upload script: API automation
├── domain-lists-dc.py          # Alternative: regex pattern generator
├── requirements.txt            # Python dependencies
├── .env.example                # Credentials template
├── .gitignore                  # Excludes sensitive data
├── LICENSE                     # MIT License
├── README.md                   # This file
└── lists/                      # Generated CSV files (gitignored)
    ├── adguard_domains_*.csv   # Domain lists (145 files)
    └── adguard_ips_1.csv       # IP list (1 file)
```

### What Gets Generated

These files are automatically downloaded/created when you run the scripts:

- `filter.txt` - Downloaded AdGuard DNS filter (3.6 MB, gitignored)
- `lists/adguard_domains_1.csv` through `lists/adguard_domains_145.csv`
- `lists/adguard_ips_1.csv`

All generated files are gitignored and not tracked in the repository.

## Command Reference

### generate-lists.py

```bash
# Use default AdGuard filter
python3 generate-lists.py

# Use custom filter
python3 generate-lists.py https://example.com/filter.txt
python3 generate-lists.py ./local-filter.txt
```

### upload_to_cloudflare.py

```bash
# Interactive mode (prompts for confirmation)
python3 upload_to_cloudflare.py

# Non-interactive mode (for cron jobs)
python3 upload_to_cloudflare.py --auto-approve
python3 upload_to_cloudflare.py -y  # short form

# Dry run (show what would be uploaded)
python3 upload_to_cloudflare.py --dry-run

# Get help
python3 upload_to_cloudflare.py --help
```

## Cloudflare Reference

### Gateway List Types

| UI Name | API Type | Used For | Example |
|---------|----------|----------|---------|
| Hostname | `DOMAIN` | Domain blocking | `ads.example.com` |
| IP | `IP` | IP blocking | `198.23.198.110` |
| URL | `URL` | URL filtering | `https://example.com/path` |
| Email | `EMAIL` | Email filtering | `spam@example.com` |

**Important:** Use `DOMAIN` type for domains (not `HOSTNAME`). The UI shows "Hostname" but the API uses `DOMAIN`.

### List Limits

| Plan | Entries/List | File Size | Total Lists |
|------|-------------|-----------|-------------|
| Standard | 1,000 | 2 MB | Unlimited |
| Enterprise | 5,000 | 2 MB | Unlimited |

### DNS Policy Traffic Selectors

```javascript
// For domain lists
any(dns.domains[*] in $list_id)

// For IP lists
any(dns.resolved_ips[*] in $list_id)
```

**Common mistake:** Using `dns.domains[*]` for IP lists will cause an error: "list has type IP but should have type Host"

## Security Notes

- `.env` is gitignored - never commit credentials
- `.env.example` contains only placeholder values
- The upload script validates credentials before starting
- API token should use "Edit Cloudflare Zero Trust" permission template
- All generated files (`filter.txt`, CSV files) are gitignored

## Resources

- [AdGuard DNS Filter](https://github.com/AdguardTeam/FiltersRegistry)
- [Cloudflare Zero Trust Docs](https://developers.cloudflare.com/cloudflare-one/)
- [DNS Policies Documentation](https://developers.cloudflare.com/cloudflare-one/policies/gateway/dns-policies/)
- [Gateway API Reference](https://developers.cloudflare.com/api/operations/zero-trust-gateway-rules-create-zero-trust-gateway-rule)

## License

MIT License - see [LICENSE](LICENSE) file for details.

The AdGuard DNS Filter has its own license - see the [AdGuard Filters Repository](https://github.com/AdguardTeam/AdguardFilters).

## Disclaimer

Use at your own risk. Blocking 144K+ domains may break website functionality. Always test in a controlled environment before production deployment.

## Credits

- AdGuard Team for maintaining the DNS filter
- Cloudflare for Zero Trust Gateway
