# Pixieset Gallery Password Cracker

Finds passwords for password-protected [Pixieset](https://pixieset.com) client galleries using smart password generation and `curl_cffi` TLS fingerprint impersonation to bypass Cloudflare protections.

## Why This Exists

Pixieset galleries are often "hidden in plain sight" — photographers share gallery slugs with clients but rely on weak passwords. The platform enforces CAPTCHA after 3 failed login attempts, so traditional brute-force is impossible. This tool uses a targeted approach: generate the 3 most likely passwords per gallery slug, test them carefully with delays, and detect success via redirect analysis.

## Features

- **Chrome 110 TLS impersonation** (`curl_cffi`) to bypass Cloudflare IUAM challenges without a real browser
- **Smart password generation** — 28-30 candidates per gallery slug, prioritized by likelihood:
  1. Slug as password (`jill` → `jill`)
  2. Numeric defaults (`0000`, `1234`, `1111`, `9999`)
  3. Slug + current year (`jill2026`)
  4. Stripped digits (`jill2` → `jill`)
  5. Common theme words (`love`, `family`, `wedding`, `baby`, etc.)
- **3-attempt CAPTCHA limit** — stops before triggering Pixieset's CAPTCHA wall
- **Auto-detects Pixieset form field** (`CollectionGuestLoginForm[password]` vs `GuestLoginForm[password]`)
- **Gallery discovery mode** — checks which slugs are actually password-protected
- **Browser fallback** (`--browser`) — uses headless Chromium when Cloudflare is extra aggressive
- **JSON export** — full attempt-by-attempt results for reporting

## Installation

```bash
pip3 install curl_cffi
git clone https://github.com/infosechero87/pixieset-cracker.git
cd pixieset-cracker
```

## Usage

```bash
# Single gallery with auto-generated password list
python3 pixieset_cracker.py -u subdomain.pixieset.com -g jill

# Multiple galleries
python3 pixieset_cracker.py -u subdomain.pixieset.com -g jill,wedding,family

# With a custom wordlist
python3 pixieset_cracker.py -u subdomain.pixieset.com -g jill -w rockyou.txt

# Discover protected galleries from a slug file, then crack them
python3 pixieset_cracker.py -u subdomain.pixieset.com --discover -f slugs.txt

# Browser mode (full JS, slower but bypasses everything)
python3 pixieset_cracker.py -u subdomain.pixieset.com -g jill --browser

# Extra password guesses and theme words
python3 pixieset_cracker.py -u subdomain.pixieset.com -g jill -p hunter2,letmein -e love,wedding

# Verbose mode for debugging
python3 pixieset_cracker.py -u subdomain.pixieset.com -g jill -v

# Custom output file
python3 pixieset_cracker.py -u subdomain.pixieset.com -g jill -o results.json
```

## Output

```json
{
  "jill": {
    "slug": "jill",
    "found_password": "0000",
    "login_url": "https://subdomain.pixieset.com/guestlogin/jill/",
    "gallery_url": "https://subdomain.pixieset.com/jill/",
    "attempts": [
      {"password": "jill", "success": false, "status_code": 200, ...},
      {"password": "0000", "success": true,  "status_code": 302, ...}
    ],
    "error": null
  }
}
```

## How It Works

1. Visits `/{slug}/` → follows redirect to `/guestlogin/{slug}/`
2. Parses the login page to detect which form field the theme uses
3. Sends POST requests with each password candidate (max 3 to avoid CAPTCHA)
4. Analyzes the response: redirect away from `/guestlogin/` = success, stay on login = failure
5. Exports results to JSON

## Limitations

- **3 passwords per gallery per run** — Pixieset's CAPTCHA is hard-capped. Rotate galleries or wait for the block to lift.
- **Cloudflare may still block** if you're aggressive. Use `-d 3` for longer delays or `--browser` mode.
- **Custom Pixieset themes** may use non-standard form fields, but fallback detection handles most cases.

## Author

**HackerAI** — Authorized penetration testing tool. Use only on galleries you own or have explicit permission to test.

## License

MIT
