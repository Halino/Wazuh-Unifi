# UniFi log parser for Wazuh

This project provides **decoders** and **rules** so Wazuh can ingest and analyze UniFi logs (CEF export and device syslog).

## What's included

| File | Purpose |
|------|--------|
| `wazuh/decoders/unifi_decoders.xml` | Decoders for UniFi CEF and device syslog |
| `wazuh/rules/unifi_rules.xml` | Rules to categorize, alert, and correlate UniFi events |
| `wazuh/ossec-unifi.conf.snippet` | Example `ossec.conf` snippet for remote syslog |
| `tests/sample_logs.txt` | Sample log lines for testing with `wazuh-logtest` |

## Supported log sources

1. **UniFi CEF export (SIEM)**
   Logs from **Settings > Control Plane > Integrations > Activity Logging** when you send logs to a SIEM/syslog server. Format: `CEF:0|Ubiquiti|UniFi Network|...`

2. **UniFi device syslog**
   Raw syslog from UniFi devices (APs, switches, gateways), e.g. `hostapd`, `ath*`, STA association/disassociation.

## Deployment

### 1. Copy decoder and rules to the Wazuh manager

On the Wazuh manager:

```bash
# Decoders
sudo cp wazuh/decoders/unifi_decoders.xml /var/ossec/etc/decoders/

# Rules
sudo cp wazuh/rules/unifi_rules.xml /var/ossec/etc/rules/
```

### 2. (Optional) Receive syslog on the manager

If UniFi (or your SIEM) sends syslog **to the Wazuh manager**, add the snippet from `wazuh/ossec-unifi.conf.snippet` into `/var/ossec/etc/ossec.conf` inside `<ossec_config>`:

- Set `<allowed-ips>` to your UniFi/network range (e.g. `192.168.0.0/16`).
- Use `udp` for classic syslog; use `tcp` and port 514 if your sender uses TCP.

### 3. Alternative: syslog to file, then Wazuh reads the file

If another host (e.g. rsyslog) receives UniFi syslog and writes to a file, point Wazuh at that file.

**Example rsyslog** (e.g. `/etc/rsyslog.d/unifi.conf`) to write UniFi messages to a file:

```
# Receive UDP syslog on 514, write UniFi to file
module(load="imudp")
input(type="imudp" port="514")
if $msg contains "CEF:0|Ubiquiti" or $msg contains "hostapd" or $msg contains "ath" then {
  action(type="omfile" file="/var/log/unifi.log")
}
```

**Wazuh** - on the host that has `/var/log/unifi.log` (manager or agent), add to `ossec.conf` inside `<ossec_config>`:

```xml
<localfile>
  <location>/var/log/unifi.log</location>
  <log_format>syslog</log_format>
</localfile>
```

- If the file is on the **manager**, add this in the manager's `ossec.conf`.
- If the file is on another server, install a Wazuh **agent** there and add this block to the **agent** `ossec.conf` (or equivalent) so the agent forwards that log to the manager.

### 4. Restart Wazuh

```bash
sudo systemctl restart wazuh-manager
```

## UniFi side: sending logs to Wazuh

- **CEF (recommended)**
  In UniFi: **Settings > Control Plane > Integrations > Activity Logging** > choose **SIEM Server** > set your Wazuh manager (or syslog relay) **IP** and **port** (e.g. **514**).
  Logs will be in CEF and decoded by `unifi_decoders.xml`.

- **Device syslog**
  On the UniFi controller / device, set **Remote syslog** to the same IP and port. Devices will send hostapd-style messages; the same decoders/rules handle them.

## Rule groups and levels

| Group / concept | Examples |
|----------------|----------|
| `unifi` | All UniFi events |
| Admin / config | Admin accessed, config changes (level 3-5) |
| Client WiFi | Client connected/disconnected/roaming (level 2) |
| Security | Threat detected and blocked, honeypot, firewall block (level 5-8) |
| WAN / performance | Failover, high latency, packet loss (level 4-5) |
| Power | PoE / AP underpowered, PoE availability exceeded (level 5-6) |
| Correlation | Brute-force, deauth flapping, repeated blocks, multi-threat (level 8-12) |

In the Wazuh UI you can filter with e.g. `rule.groups:unifi` or by rule ID range `100100`-`100218`.

## Correlation / frequency rules

These rules fire when a base rule triggers repeatedly within a time window:

| Rule ID | Triggers on | Frequency / Window | Level | Description |
|---------|------------|-------------------|-------|-------------|
| 100210 | 100204 (RADIUS) | 5 in 60 s | 10 | Possible RADIUS brute-force |
| 100211 | 100201 (disassociated) | 10 in 60 s | 8 | Rapid disassociations (deauth / flapping) |
| 100212 | 100111 (firewall block) | 10 in 120 s, same src | 8 | Repeated firewall blocks (scanning) |
| 100213 | 100109 (threat) | 3 in 120 s | 12 | Multiple threat detections |
| 100214 | 100120 (internal threat) | 3 in 300 s, same src | 12 | Multiple internal threats from one host |

### Aggressive correlation rules

These are **more sensitive and potentially noisier**. They all add `aggressive` to `rule.groups` so you can filter or treat them differently:

| Rule ID | Triggers on | Frequency / Window | Level | Description |
|---------|------------|-------------------|-------|-------------|
| 100215 | 100111 (firewall block) | 3 in 300 s, same src | 10 | Aggressive: early firewall scan detection |
| 100216 | 100204 (RADIUS) | 3 in 300 s, same src | 10 | Aggressive: early RADIUS brute-force suspicion |
| 100217 | 100214 (internal threat) | 2 in 900 s, same src | 14 | Aggressive: persistent internal threat source |
| 100218 | 100109 (threat) | 2 in 600 s, same src | 14 | Aggressive: source triggering multiple threat detections |

## MITRE ATT&CK mappings

Rules include `<mitre>` tags so events appear in the Wazuh MITRE dashboard:

| Technique | ID | Rules |
|-----------|-----|-------|
| Valid Accounts | T1078 | 100101 (admin access) |
| Impair Defenses | T1562 | 100102 (config changes) |
| Hardware Additions | T1200 | 100103 (device adopted) |
| Service Stop | T1489 | 100104, 100112 (device offline, WAN failover) |
| Application Layer Protocol | T1071 | 100109, 100111, 100213 (threats, firewall) |
| Network Service Scanning | T1046 | 100110, 100212 (honeypot, repeated blocks) |
| Brute Force | T1110 | 100210 (RADIUS brute-force) |
| Network Denial of Service | T1498 | 100211 (deauth flapping) |

## Testing decoders and rules

Use `wazuh-logtest` on the manager:

```bash
/var/ossec/bin/wazuh-logtest
```

Paste a sample line, for example:

```
CEF:0|Ubiquiti|UniFi Network|9.3.33|544|Admin Accessed UniFi Network|1|UNIFIcategory=System UNIFIhost=Office UDM Pro src=105.5.138.59 msg=Admin accessed.
```

You should see the `unifi-cef` decoder and the corresponding rule (e.g. 100101) match.

A full set of annotated sample logs is in `tests/sample_logs.txt` -- each line notes the expected decoder and rule ID.

## File layout

```
Wazuh-Unifi/
|-- README.md
|-- LICENSE
|-- CHANGELOG.md
|-- .gitignore
|-- tests/
|   |-- sample_logs.txt
|-- wazuh/
|   |-- decoders/
|   |   |-- unifi_decoders.xml
|   |-- rules/
|   |   |-- unifi_rules.xml
|   |-- ossec-unifi.conf.snippet
```

## Compatibility

Verified against the official [UniFi System Logs & SIEM Integration](https://help.ui.com/hc/en-us/articles/33349041044119-UniFi-System-Logs) documentation as of February 2026. Tested with **UniFi Network Application 10.0.x** (latest: 10.0.162).

| Component | Status |
|-----------|--------|
| **CEF (SIEM export)** | Compatible with UniFi Network 9.3.x and 10.0.x. Format is unchanged: `CEF:0\|Ubiquiti\|UniFi Network\|Version\|EventID\|Name\|Severity\|Extension`. Decoder accepts optional "UniFi Network Application" product name for future versions. |
| **CEF keys** | Parser extracts standard header + `src` (IPv4/IPv6), `UNIFIcategory`, `UNIFIsubCategory`, `UNIFIadmin`, `UNIFIclientMac`. Other extension keys (e.g. `UNIFIutcTime`, `UNIFIdeviceName`, `UNIFIclientIp`) are preserved in `extra_data` and do not break decoding. |
| **Event names** | Rules match all current event names from the [official docs](https://help.ui.com/hc/en-us/articles/33349041044119-UniFi-System-Logs): Admin Accessed/Made Config Changes, Device Adopted/Offline, WiFi Client Connected/Disconnected/Roaming, Threat Detected and Blocked, Honeypot Triggered, Blocked by Firewall, WAN Failover, High Latency/Packet Loss, Insufficient PoE Output/PoE Availability Exceeded/AP Underpowered. |
| **Log categories** | Monitoring (Guest Hotspot, WiFi, Wired, Status), Internet (Outage & Failover, Performance), Power (PoE, Redundancy), Security (Firewall, Honeypot, Intrusion Prevention), System (Admin Activity, Devices, Network, VPN, WiFi, Wired). VPN events under System are caught by the catch-all rule (100199). |
| **CyberSecure / Traffic Flows** | Traffic Flow logs (DPI/IDS) are not yet exported via CEF per the [official Traffic Flows docs](https://help.ui.com/hc/en-us/articles/32201256219799). They are available as CSV and NetFlow/IPFIX only. When Ubiquiti adds CEF support for traffic flows, new decoders/rules may be needed. |
| **Device syslog** | Compatible with hostapd/ath-style logs from UniFi APs and devices forwarding to remote syslog (STA association/disassociation, RADIUS). Device firmware may also emit JSON; this parser targets the classic syslog format. |

If Ubiquiti adds new event types, the catch-all rule (100199) keeps unknown CEF events under the `unifi` group without alerting. Add specific rules as needed.

## References

- [UniFi System Logs & SIEM Integration](https://help.ui.com/hc/en-us/articles/33349041044119-UniFi-System-Logs-SIEM-Integration)
- [Wazuh - Configuring syslog](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/syslog.html)
- [Wazuh - Custom decoders](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/custom.html)
