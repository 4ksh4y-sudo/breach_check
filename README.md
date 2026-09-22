# breachcheck

A tiny, dependency-free CLI to check whether an email address has appeared in
known data breaches, and whether a password has been seen in breach dumps.

**Free by default.** No API key, no signup, no account.

## What it does

- **Email check** — which breaches an address appears in, and what data classes
  were exposed (emails, passwords, names, IPs, etc.). 

## Install

No dependencies, Python 3.7+.

```bash
git clone https://github.com/<you>/breachcheck.git
cd breachcheck
python3 breachcheck.py --help
