# Investigation Playbook — Midnight Blizzard RDP spear-phish (Project 1)

**Primary sources:**  
- Microsoft blog: https://www.microsoft.com/en-us/security/blog/2024/10/29/midnight-blizzard-conducts-large-scale-spear-phishing-campaign-using-rdp-files/  
- CERT-UA alert: https://cert.gov.ua/article/6281076

## Goal
Triage suspected RDP spear-phish incidents, determine scope of compromise, collect forensic artifacts, and contain/remove adversary access.

---

## Quick triage (0–30 minutes)
1. **Identify victim(s) & email details**
   - Pull inbound EML from gateway/quarantine. Save EML and headers.
   - Record sender envelope & sending IP (mail-server logs), DKIM/SPF/DMARC status.
   - Extract attachment file (`.rdp`), compute SHA256/SHA1/MD5.

2. **Check user activity**
   - Query endpoint for `mstsc.exe` process creation events in ±15 minutes of email receipt.
   - Sysmon: EventID 1 where Image endswith `\mstsc.exe` and CommandLine contains `.rdp`.
   - Windows 4688 if Sysmon unavailable.

3. **Check network activity**
   - Query firewall / netflow for outbound TCP flows from the host:dst port 3389 in the same time window.
   - Identify destination IP/domain and note cloud provider / geolocation.

If evidence shows the `.rdp` was opened and outbound RDP occurred → proceed to full investigation & containment.

---

## Full investigation (30–180 minutes)
1. **Timeline & correlation**
   - Build host timeline: EML received → `.rdp` opened (process create) → outbound RDP (flow) → any subsequent suspicious processes / file writes.
   - Correlate with authentication logs (4624 / 4625). Look for Logon Type 10 (RemoteInteractive).

2. **Endpoint collection**
   - If suspicious, isolate host (network quarantine) and take memory + disk snapshot (EDR/forensic tools).
   - Collect Sysmon logs, Windows event logs, running processes, scheduled tasks, registry autoruns, service list.
   - Capture network capture (pcap) for the RDP session if possible.

3. **Credential activity**
   - Check for processes that accessed `lsass.exe` (LSASS handle open) or spawned tools known for credential dumping (procdump, comsvcs.dll misuse, etc.).
   - Check for new privileged authentications or lateral logons from the compromised host.

4. **Search for persistence**
   - Look for new Run keys, scheduled tasks, services, WMI event subscriptions, or new user accounts.
   - Query EDR for new or modified autorun artifacts.

5. **Network hunt**
   - Hunt across netflow/proxy logs for other hosts contacting the same destination IP/domain on 3389 or other ports.
   - Look for patterns of beaconing (periodic callbacks) to suspect domains.

---

## Containment & remediation
1. **Contain**
   - Isolate the affected host(s) from the network.
   - Revoke or reset credentials that may have been exposed (prioritize privileged/service accounts).
   - Block attacker destination IPs/domains at perimeter and in DNS if known.

2. **Remediate**
   - If credential theft confirmed, rotate passwords and reissue credentials. Enforce MFA on affected accounts.
   - Rebuild compromised hosts from known-good images if persistence or malware confirmed.
   - Remove persistence artifacts and validate via EDR scans.

3. **Recover**
   - Validate system integrity, patch, and bring systems back on the network after confirmation.
   - Monitor affected accounts and hosts for at least 30 days for re-emergence.

---

## Reporting & intel sharing
- Produce an incident timeline with EML, attachment hash, process creation logs, outbound flow evidence, and any POI (IPs/domains).
- Share IOCs with internal TI and, when appropriate, with ISACs and vendor contacts (e.g., Microsoft / CERT-UA) following policy.
- Sanitize any victim PII before external sharing.

---

## Hunting queries (examples)
- **Host process:** Sysmon/EventID 1 where Image endswith `\mstsc.exe` and CommandLine contains ".rdp".
- **Network:** Netflow where dst_port == 3389 and dst_ip not in internal/approved allowlist.
- **Email:** Inbound mail where attachment_extension == ".rdp" and sender_domain not in trusted whitelist.

---

## Notes & safety
- Only publish artifacts that are publicly available in vendor/CERT advisories. Sanitize or redact any victim-identifying information when sharing externally.
- Always operate on isolated lab environments when emulating attack behavior for testing detection.
