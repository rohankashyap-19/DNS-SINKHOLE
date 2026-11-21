# DNS Guardian – Suspicious Domain Detection

Enter a domain → analyze its DNS records → check characteristics & reputation → get a 0–100 risk score → see *why* it looks suspicious.

## Run
```
python dns_guardian.py google.com
python dns_guardian.py paypa1-secure-login.xyz
python dns_guardian.py paypa1-secure-login.xyz --offline   # name analysis only (no internet)
python dns_guardian.py evil-login.top --json               # machine-readable output
```
Requires Python 3.8+. No installation needed. Optional: `pip install dnspython` for MX/NS/TXT records.

## Files
- `dns_guardian.py` – the whole tool (~150 lines)
- `blocklist.txt` – sample reputation list (add your own domains)
- `DNS_Guardian_Documentation.pdf` – project report
- `DNS_Guardian_Presentation.pptx` – 6 slides with speaker notes

## Risk levels
0–24 LOW · 25–49 MEDIUM · 50–100 HIGH

*Heuristic aid only – verify before blocking a domain.*
