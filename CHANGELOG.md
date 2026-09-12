# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Documentation
- **Rule file load-order warning**: Added a note to the deployment section explaining that `wazuh-analysisd` merges the stock ruleset and `etc/rules/` into one alphabetical-by-filename load order (directory of origin is ignored), that Wazuh's stock rule files are all digit-prefixed, and why `unifi_rules.xml`'s letter-leading name and self-contained anchors keep it safe from that trap — plus guidance for anyone renaming it or layering more custom rules on top.

### Verified
- **Verified against official Ubiquiti docs** (February 2026): All decoders, rules, and event names cross-checked with the [UniFi System Logs & SIEM Integration](https://help.ui.com/hc/en-us/articles/33349041044119-UniFi-System-Logs) documentation and the [Traffic Flows](https://help.ui.com/hc/en-us/articles/32201256219799) page.
- **UniFi Network Application 10.0.x** (latest: 10.0.162): CEF format unchanged (`CEF:0|Ubiquiti|UniFi Network|...`).
- **CyberSecure Traffic Flows**: Not yet available via CEF export (CSV and NetFlow/IPFIX only per official docs).

### Fixed
- **Rule ordering bug**: Swapped rules 100201/100202 so "disassociated" is evaluated before "associated" (substring match conflict).
- **README typo**: Corrected `<locfile>` to `<localfile>` in the rsyslog-to-file example.
- **Rule 100109 description**: Restored to "detected and blocked" to match the official event name "Threat Detected and Blocked" per Ubiquiti docs.

### Improved
- **IPv6 support**: `unifi-cef-srcip` decoder now captures both IPv4 and IPv6 source addresses.
- **UNIFIadmin with spaces**: Admin decoder now uses `<pcre2>` (Wazuh 4.2+) to capture values containing spaces (reads up to the next CEF key).
- **Device syslog prematch**: Removed overly broad `UniFi` token; narrowed to `ubnt-` to avoid accidental overlap with CEF decoder.
- **Sample logs updated**: All samples now include `UNIFIsubCategory` and use official event names from Ubiquiti docs. Added verification notes and version references.

### Added
- **Gateway firewall (netfilter) support** — new decoder `unifi-fw` and rules `100230`-`100234`. UniFi gateways (UDM/UXG/USG) log firewall rule hits to syslog when **Log** is enabled on a rule (`[<ZONE>-<ACTION>-<N>] DESCR="..." SRC=... DST=... PROTO=... DPT=...`):
  - `100231` ACCEPT (silenced, level 0), `100232` DROP/REJECT (level 4), `100233` **DNAT/SNAT** = inbound to a port-forwarded/exposed service (level 4, MITRE T1190), `100234` repeated blocks from one source in 120 s = port scan (level 10, MITRE T1046).
  - The action code is matched as a generic `[A-Za-z]+` so **DNAT** hits are captured, not silently ignored (a narrow `[ADR]` match misses inbound access to exposed services).
  - Firewall sample lines added to `tests/sample_logs.txt` (RFC 5737 documentation IPs).
- **New rule 100117**: WiFi Client Roaming (Monitoring category, level 2). Event listed in official docs under Monitoring > WiFi.
- **New rule 100118**: PoE Availability Exceeded (Power category, level 5). Event listed in official docs under Power > Redundancy.
- **New decoder `unifi-cef-subcategory`**: Extracts `UNIFIsubCategory` CEF key (e.g. Admin, WiFi, Firewall, PoE).
- **New decoder `unifi-cef-clientmac`**: Extracts `UNIFIclientMac` CEF key for client tracking.
- **MITRE ATT&CK mappings**: Rules for admin access (T1078), config changes (T1562), device adopted (T1200), device offline (T1489), threats (T1071), honeypot (T1046), firewall blocks (T1071), WAN failover (T1489).
- **Frequency / correlation rules**:
  - 100210: Multiple RADIUS events in 60s (brute-force, T1110).
  - 100211: Rapid disassociations in 60s (deauth attack, T1498).
  - 100212: Repeated firewall blocks from same source in 120s (scanning, T1046).
  - 100213: Multiple threat detections in 120s (T1071).
- **Sample test logs**: `tests/sample_logs.txt` with representative log lines and expected decoder/rule annotations.
- **LICENSE**: MIT license.
- **CHANGELOG**: This file.
- **.gitignore**: Ignore OS, editor, and runtime files.
