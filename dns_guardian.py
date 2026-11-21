#!/usr/bin/env python3
"""
DNS Guardian - Suspicious Domain Detection
Enter a domain -> analyze DNS records -> check characteristics & reputation
-> generate a risk score -> explain why the domain looks suspicious.

Uses only the Python standard library (dnspython is optional, for MX/NS/TXT).
Usage:  python dns_guardian.py example.com
        python dns_guardian.py paypa1-secure-login.xyz --offline
"""
import argparse, json, math, re, socket, sys, difflib, urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

try:
    import dns.resolver  # optional
    HAVE_DNSPYTHON = True
except ImportError:
    HAVE_DNSPYTHON = False

# ---------- Reference data (small, easy to explain) ----------
SUSPICIOUS_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click",
                   "link", "zip", "country", "support", "loan", "icu", "buzz"}
KEYWORDS = ["login", "secure", "verify", "update", "account", "bank", "paypal",
            "wallet", "free", "bonus", "gift", "support", "billing", "signin"]
BRANDS = ["google", "facebook", "paypal", "amazon", "microsoft", "apple",
          "netflix", "instagram", "whatsapp", "sbi", "hdfcbank", "icicibank"]
BLOCKLIST_FILE = Path(__file__).with_name("blocklist.txt")


# ---------- Step 1: input ----------
def normalize(domain: str) -> str:
    d = domain.strip().lower()
    d = re.sub(r"^https?://", "", d).split("/")[0].split(":")[0]
    if not re.fullmatch(r"[a-z0-9.-]+\.[a-z0-9-]{2,}", d):
        raise ValueError(f"'{domain}' does not look like a valid domain name")
    return d


# ---------- Step 2: DNS records ----------
def get_dns_records(domain: str) -> dict:
    rec = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": []}
    if HAVE_DNSPYTHON:
        for rtype in rec:
            try:
                ans = dns.resolver.resolve(domain, rtype, lifetime=4)
                rec[rtype] = [r.to_text() for r in ans]
            except Exception:
                pass
    else:  # fallback: only A / AAAA through the OS resolver
        try:
            for info in socket.getaddrinfo(domain, None):
                key = "A" if info[0] == socket.AF_INET else "AAAA"
                if info[4][0] not in rec[key]:
                    rec[key].append(info[4][0])
        except socket.gaierror:
            pass
    return rec


def domain_age_days(domain: str):
    """Registration age via the public RDAP service. None if unavailable."""
    try:
        root = ".".join(domain.split(".")[-2:])
        with urllib.request.urlopen(f"https://rdap.org/domain/{root}", timeout=6) as r:
            data = json.load(r)
        for ev in data.get("events", []):
            if ev.get("eventAction") == "registration":
                created = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                return (datetime.now(timezone.utc) - created).days
    except Exception:
        pass
    return None


# ---------- Step 3: characteristics & reputation ----------
def entropy(s: str) -> float:
    c = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values())


def load_blocklist() -> set:
    if BLOCKLIST_FILE.exists():
        return {l.strip().lower() for l in BLOCKLIST_FILE.read_text().splitlines()
                if l.strip() and not l.startswith("#")}
    return set()


def analyze(domain: str, records: dict, age_days, offline: bool) -> list:
    """Return a list of (points, reason). Each rule is simple and explainable."""
    findings = []
    parts = domain.split(".")
    tld, name = parts[-1], parts[-2]
    clean = name.replace("-", "")

    # Reputation
    if domain in load_blocklist() or ".".join(parts[-2:]) in load_blocklist():
        findings.append((60, "Domain is listed in the local blocklist (known bad)"))

    # Characteristics
    if tld in SUSPICIOUS_TLDS:
        findings.append((15, f"Uses a high-abuse TLD (.{tld})"))
    if name.startswith("xn--") or "xn--" in domain:
        findings.append((15, "Punycode (xn--) can hide look-alike Unicode characters"))
    if len(name) > 20:
        findings.append((10, f"Very long domain name ({len(name)} characters)"))
    if name.count("-") >= 2:
        findings.append((10, f"Many hyphens ({name.count('-')}) - common in phishing names"))
    digits = sum(ch.isdigit() for ch in name)
    if digits >= 3:
        findings.append((10, f"Contains many digits ({digits})"))
    if len(clean) >= 8 and entropy(clean) > 3.5:
        findings.append((15, f"Looks randomly generated (entropy {entropy(clean):.2f}) - DGA-like"))
    if len(parts) > 4:
        findings.append((10, f"Deep subdomain chain ({len(parts)} labels)"))
    hits = [k for k in KEYWORDS if k in domain]
    if hits:
        findings.append((min(10 * len(hits), 20), f"Bait keywords in name: {', '.join(hits)}"))

    # Brand look-alike (typosquatting): paypa1 ~ paypal
    norm = name.replace("1", "l").replace("0", "o").replace("3", "e")
    for brand in BRANDS:
        if brand in norm and name != brand:
            findings.append((20, f"Contains brand name '{brand}' but is not the real site"))
            break
        ratio = difflib.SequenceMatcher(None, clean.replace("1", "l").replace("0", "o"), brand).ratio()
        if clean != brand and ratio >= 0.85:
            findings.append((25, f"Looks like a typo of '{brand}' (similarity {ratio:.0%})"))
            break

    # DNS-record based signals
    if not offline:
        if not (records["A"] or records["AAAA"]):
            findings.append((10, "Domain does not resolve (no A/AAAA record)"))
        if HAVE_DNSPYTHON and records["A"] and not records["MX"]:
            findings.append((5, "No MX record - no real mail setup"))
        if len(records["A"]) == 1 and re.fullmatch(r"(10|127|192\.168)\..*", records["A"][0]):
            findings.append((20, "Resolves to a private/local IP address"))
        if age_days is not None and age_days < 30:
            findings.append((25, f"Newly registered domain ({age_days} days old)"))
        elif age_days is not None and age_days < 180:
            findings.append((10, f"Fairly young domain ({age_days} days old)"))
    return findings


# ---------- Step 4: risk score ----------
def risk_level(score: int) -> str:
    return "LOW" if score < 25 else "MEDIUM" if score < 50 else "HIGH"


def main():
    ap = argparse.ArgumentParser(description="DNS Guardian - suspicious domain detection")
    ap.add_argument("domain")
    ap.add_argument("--offline", action="store_true", help="skip network lookups (name analysis only)")
    ap.add_argument("--json", action="store_true", help="print result as JSON")
    a = ap.parse_args()

    try:
        domain = normalize(a.domain)
    except ValueError as e:
        sys.exit(f"Error: {e}")

    records = {k: [] for k in ("A", "AAAA", "MX", "NS", "TXT")} if a.offline else get_dns_records(domain)
    age = None if a.offline else domain_age_days(domain)
    findings = analyze(domain, records, age, a.offline)
    score = min(sum(p for p, _ in findings), 100)
    level = risk_level(score)

    if a.json:
        print(json.dumps({"domain": domain, "score": score, "level": level, "records": records,
                          "age_days": age, "reasons": [r for _, r in findings]}, indent=2))
        return

    # ---------- Step 5: explanation ----------
    print(f"\n=== DNS GUARDIAN REPORT: {domain} ===")
    print("\n[1] DNS records")
    if a.offline:
        print("   (skipped - offline mode)")
    else:
        for k, v in records.items():
            print(f"   {k:5}: {', '.join(v) if v else '-'}")
        print(f"   Domain age: {f'{age} days' if age is not None else 'unknown'}")
    print(f"\n[2] Risk score : {score}/100  ->  {level}")
    print("\n[3] Why?")
    if findings:
        for p, r in sorted(findings, reverse=True):
            print(f"   +{p:<3} {r}")
    else:
        print("   No suspicious indicators found.")
    print("\nNote: this is a heuristic aid, not proof. Verify before blocking.\n")


if __name__ == "__main__":
    main()
