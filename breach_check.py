#!/usr/bin/env python3
"""
breachcheck - CLI tool to check email/password exposure in known data breaches.

Created by K1ssm3
GitHub: https://github.com/4ksh4y-sudo

FREE BY DEFAULT:
  - Email breach lookup  -> XposedOrNot (no API key, no signup)
  - Password check       -> HIBP Pwned Passwords k-anonymity API (no key, no signup)
OPTIONAL PAID:
  - Email breach lookup  -> Have I Been Pwned (set HIBP_API_KEY, pass --provider hibp)

Design principle: this tool NEVER retrieves, stores, or displays anyone's actual
breached password. It only reports exposure status.

Usage:
    python3 breachcheck.py --email someone@example.com
    python3 breachcheck.py --email someone@example.com --check-password
    python3 breachcheck.py --email someone@example.com --json
    python3 breachcheck.py --batch emails.txt
    HIBP_API_KEY=xxx python3 breachcheck.py --email someone@example.com --provider hibp
"""

import argparse
import getpass
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# --- Creator / version metadata --------------------------------------------
__version__ = "1.1.0"
__author__ = "K1ssm3"
__author_handle__ = "K1ssm3"
__author_url__ = "https://github.com/K1ssm3"

# --- Free email provider (no key) ------------------------------------------
XON_ANALYTICS_URL = "https://api.xposedornot.com/v1/breach-analytics?email={}"

# --- Paid email provider (optional) ----------------------------------------
HIBP_BREACH_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{}"

# --- Password API (always free, keyless) -----------------------------------
HIBP_PWNED_PASSWORDS_URL = "https://api.pwnedpasswords.com/range/{}"

USER_AGENT = f"breachcheck-cli/{__version__} (by {__author__}; personal security awareness tool)"


class BreachCheckError(Exception):
    pass


# ---------------------------------------------------------------------------
# Creator banner
# ---------------------------------------------------------------------------
def show_banner():
    print(r"""
   __                     __        __        __
  / /  ___ ___ ________ _/ /  ___  / /__ ____/ /_
 / _ \/ -_) _ `/ __/ _ `/ _ \/ _ \/  '_/ -_) __/
/_.__/\__/\_,_/_/  \_,_/_//_/\___/_/\_\\__/\__/
""")
    print(f"  breachcheck v{__version__}  ·  free & keyless breach exposure checker")
    print(f"  created by {__author__} (@{__author_handle__})")
    print(f"  {__author_url__}")
    print()


# ---------------------------------------------------------------------------
# Free provider: XposedOrNot
# ---------------------------------------------------------------------------
def check_email_xposedornot(email, timeout=15):
    """
    Query XposedOrNot's free API for breaches an email appears in.
    Returns a list of normalized breach dicts:
        {"Title": ..., "BreachDate": ..., "DataClasses": [...], "IsVerified": bool}
    No API key required. No passwords are ever returned.
    """
    url = XON_ANALYTICS_URL.format(urllib.parse.quote(email))
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return []
        if e.code == 429:
            raise BreachCheckError("Rate limited by XposedOrNot. Try again later.")
        raise BreachCheckError(f"XposedOrNot API error: HTTP {e.code}")
    except urllib.error.URLError as e:
        raise BreachCheckError(f"Network error contacting XposedOrNot: {e}")

    return _normalize_xon(data)


def _normalize_xon(data):
    """Flatten XposedOrNot's several response shapes into our internal format."""
    breaches = []

    # Shape A: {"ExposedBreaches": {"Breaches_Details": [ ... ]}}
    exposed = data.get("ExposedBreaches") or {}
    details = exposed.get("Breaches_Details") or []
    for b in details:
        breaches.append({
            "Title": b.get("breach") or b.get("Breach") or "Unknown breach",
            "BreachDate": b.get("breach_date") or b.get("BreachDate") or "unknown date",
            "DataClasses": b.get("exposed_data") or b.get("ExposedData") or [],
            "IsVerified": bool(b.get("verified", True)),
        })

    # Shape B: {"BreachesSummary": {"Site": "a;b;c"}}
    if not breaches:
        summary = data.get("BreachesSummary") or {}
        site = summary.get("Site") or summary.get("site")
        if site:
            for name in [s.strip() for s in site.split(";") if s.strip()]:
                breaches.append({
                    "Title": name,
                    "BreachDate": "unknown date",
                    "DataClasses": [],
                    "IsVerified": True,
                })

    # Shape C: {"breaches": [ ... ]}
    if not breaches:
        for b in data.get("breaches", []) or []:
            breaches.append({
                "Title": b.get("name") or b.get("Name") or "Unknown breach",
                "BreachDate": b.get("date") or b.get("BreachDate") or "unknown date",
                "DataClasses": b.get("data_classes") or b.get("DataClasses") or [],
                "IsVerified": bool(b.get("verified", True)),
            })

    return breaches


# ---------------------------------------------------------------------------
# Paid provider: HIBP (only used with --provider hibp)
# ---------------------------------------------------------------------------
def get_hibp_api_key():
    key = os.environ.get("HIBP_API_KEY")
    if not key:
        raise BreachCheckError(
            "HIBP provider selected but no API key found. Either:\n"
            "    export HIBP_API_KEY='your-key-here'\n"
            "  or run without --provider hibp to use the free XposedOrNot provider.\n"
            "Get a key at https://haveibeenpwned.com/API/Key"
        )
    return key


def check_email_hibp(email, api_key, timeout=15):
    url = HIBP_BREACH_URL.format(urllib.parse.quote(email)) + "?truncateResponse=false"
    req = urllib.request.Request(
        url,
        headers={"hibp-api-key": api_key, "User-Agent": USER_AGENT},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return []
        if e.code == 401:
            raise BreachCheckError("Invalid HIBP API key.")
        if e.code == 429:
            retry_after = e.headers.get("Retry-After", "a few")
            raise BreachCheckError(f"Rate limited. Retry after {retry_after} seconds.")
        raise BreachCheckError(f"HIBP API error: HTTP {e.code}")
    except urllib.error.URLError as e:
        raise BreachCheckError(f"Network error contacting HIBP: {e}")


# ---------------------------------------------------------------------------
# Password check (free, keyless, k-anonymity)
# ---------------------------------------------------------------------------
def check_password_pwned(password):
    """
    SHA-1 the password locally; send only the first 5 hex chars to HIBP.
    The full password and full hash never leave this machine.
    Returns (is_pwned: bool, occurrence_count: int).
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    req = urllib.request.Request(
        HIBP_PWNED_PASSWORDS_URL.format(prefix),
        headers={"User-Agent": USER_AGENT, "Add-Padding": "true"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode("utf-8")
    except urllib.error.URLError as e:
        raise BreachCheckError(f"Network error contacting Pwned Passwords API: {e}")

    for line in body.splitlines():
        if ":" not in line:
            continue
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return True, int(count)
    return False, 0


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def format_breach_report(email, breaches):
    lines = []
    if not breaches:
        lines.append(f"[OK] {email} - no known breaches found.")
        return "\n".join(lines)

    lines.append(f"[!] {email} - found in {len(breaches)} breach(es):\n")
    for b in breaches:
        name = b.get("Title") or b.get("Name") or "Unknown"
        date = b.get("BreachDate", "unknown date")
        classes = ", ".join(b.get("DataClasses") or []) or "not specified"
        verified = "verified" if b.get("IsVerified") else "unverified"
        lines.append(f"  - {name} ({date}, {verified})")
        lines.append(f"      Data exposed: {classes}")
    lines.append(
        "\nRecommendation: change passwords for these services (and anywhere "
        "you reused them), enable 2FA, and use a password manager going forward."
    )
    return "\n".join(lines)


def check_email(email, provider, api_key=None):
    if provider == "hibp":
        return check_email_hibp(email, api_key)
    return check_email_xposedornot(email)


def run_single(email, provider, api_key, check_pw, as_json):
    result = {"email": email, "breaches": [], "provider": provider, "password_checked": False}
    breaches = []
    try:
        breaches = check_email(email, provider, api_key)
        result["breaches"] = breaches
    except BreachCheckError as e:
        result["error"] = str(e)

    pw_result = None
    if check_pw:
        password = getpass.getpass(f"Enter password to check for {email} (input hidden): ")
        try:
            is_pwned, count = check_password_pwned(password)
            pw_result = {"pwned": is_pwned, "occurrences": count}
            result["password_checked"] = True
            result["password_result"] = pw_result
        except BreachCheckError as e:
            result["password_error"] = str(e)
        finally:
            del password

    if as_json:
        print(json.dumps(result, indent=2))
        return

    if "error" in result:
        print(f"[ERROR] {email}: {result['error']}")
    else:
        print(format_breach_report(email, breaches))

    if pw_result:
        print()
        if pw_result["pwned"]:
            print(
                f"[!] This password has appeared in breach data "
                f"{pw_result['occurrences']:,} times. Do not use it. Change it now."
            )
        else:
            print("[OK] This password was not found in known breach data.")
    elif "password_error" in result:
        print(f"[ERROR] Password check failed: {result['password_error']}")


def run_batch(path, provider, api_key, as_json):
    with open(path) as f:
        emails = [line.strip() for line in f if line.strip()]

    all_results = []
    for i, email in enumerate(emails):
        try:
            breaches = check_email(email, provider, api_key)
            all_results.append({"email": email, "breaches": breaches, "provider": provider})
            if not as_json:
                print(format_breach_report(email, breaches))
                print("-" * 60)
        except BreachCheckError as e:
            all_results.append({"email": email, "error": str(e)})
            if not as_json:
                print(f"[ERROR] {email}: {e}")
                print("-" * 60)
        if i < len(emails) - 1:
            time.sleep(1.1)

    if as_json:
        print(json.dumps(all_results, indent=2))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description=(
            f"breachcheck v{__version__} by {__author__} - check if an email/password "
            "has been exposed in known data breaches. Free by default (XposedOrNot). "
            "Never retrieves or displays actual breached passwords."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            f"Created by {__author__} (@{__author_handle__}) - {__author_url__}\n\n"
            "Examples:\n"
            "  breachcheck.py --email you@example.com\n"
            "  breachcheck.py --email you@example.com --check-password\n"
            "  breachcheck.py --batch emails.txt --json\n"
            "  HIBP_API_KEY=xxx breachcheck.py --email you@example.com --provider hibp\n"
        ),
    )
    parser.add_argument("--email", help="Email address to check")
    parser.add_argument("--batch", help="Path to a text file, one email per line")
    parser.add_argument(
        "--check-password",
        action="store_true",
        help="Also check a password (entered interactively, hidden input) via k-anonymity",
    )
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    parser.add_argument(
        "--provider",
        choices=["xon", "hibp"],
        default="xon",
        help="Email breach provider. 'xon' = XposedOrNot (free, default). "
             "'hibp' = Have I Been Pwned (requires HIBP_API_KEY).",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Suppress the creator banner",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"breachcheck {__version__} by {__author__} (@{__author_handle__}) - {__author_url__}",
    )
    parser.add_argument(
        "--about",
        action="store_true",
        help="Show creator info and exit",
    )
    args = parser.parse_args()

    if args.about:
        show_banner()
        print("  breachcheck is a free, keyless breach exposure checker for emails and passwords.")
        print("  Password checks use k-anonymity: your password never leaves your machine.")
        print("  It reports exposure only and never displays breached passwords.")
        print()
        print(f"  Author : {__author__} (@{__author_handle__})")
        print(f"  GitHub : {__author_url__}")
        print(f"  License: MIT")
        sys.exit(0)

    if not args.email and not args.batch:
        parser.error("Provide --email or --batch")
    if args.email and args.batch:
        parser.error("Use either --email or --batch, not both")
    if args.batch and args.check_password:
        parser.error("--check-password is only supported in single-email mode")

    # Show the creator banner for human-readable runs only.
    if not args.json and not args.no_banner:
        show_banner()

    api_key = None
    if args.provider == "hibp":
        try:
            api_key = get_hibp_api_key()
        except BreachCheckError as e:
            print(f"[ERROR] {e}", file=sys.stderr)
            sys.exit(1)

    try:
        if args.email:
            run_single(args.email, args.provider, api_key, args.check_password, args.json)
        else:
            run_batch(args.batch, args.provider, api_key, args.json)
    except BreachCheckError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(130)


if __name__ == "__main__":
    main()
