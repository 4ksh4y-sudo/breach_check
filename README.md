# breachcheck

A tiny, dependency-free CLI to check whether an email address has appeared in
known data breaches, and whether a password has been seen in breach dumps.

**Free by default.** No API key, no signup, no account.

**It will never show you a breached password.** No legitimate breach service
returns plaintext passwords, and a tool that did would be a credential-harvesting
tool. `breachcheck` reports exposure status only.

## What it does

- **Email check** — which breaches an address appears in, and what data classes
  were exposed (emails, passwords, names, IPs, etc.). Powered by
  [XposedOrNot](https://xposedornot.com) (free, keyless) by default, or
  [Have I Been Pwned](https://haveibeenpwned.com) if you supply a key.
- **Password check** — whether a password appears in breach data, using HIBP's
  [k-anonymity Pwned Passwords API](https://haveibeenpwned.com/API/v3#PwnedPasswords).
  The password is SHA-1 hashed **locally**; only the first 5 hex characters of
  the hash are ever sent. The password and full hash never leave your machine.

## Install

No dependencies, Python 3.7+.

```bash
git clone https://github.com/<you>/breachcheck.git
cd breachcheck
python3 breachcheck.py --help
