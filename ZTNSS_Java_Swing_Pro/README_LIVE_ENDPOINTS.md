# Cyber Guardian — Authenticated Live Endpoint Milestone

This is an **upgrade of your uploaded Java Swing application**, not a replacement. Existing dashboard, Nmap scanner, port explanations, firewall tab and audit logs are retained. New sidebar tab: **Live Endpoints**.

## What works
- Python standard-library HTTPS controller (`endpoint/controller.py`) with SQLite device inventory, report history, enrollment events and replay-resistant report authentication.
- Explicit endpoint enrollment using a strong shared enrollment secret; unique per-device random token issued on enrollment.
- Agent (`endpoint/agent.py`) collects Windows or Linux OS, AV/EDR, encryption, admins, processes, listening sockets and firewall evidence. All evidence is `needs_review` or `unknown`; no fabricated PASS or numeric score.
- Device token protected using Windows DPAPI or Linux OS keyring (install `keyring` and configure a working backend).
- HTTPS certificate verification stays enabled. Agent refuses HTTP; Java viewer refuses HTTP.
- Java Swing Live Endpoints tab displays actual controller JSON and can refresh every 15 seconds.

## Requirements
Windows 10/11, Java JDK 17+, Python 3.10+, Nmap for existing scanner, trusted TLS certificate + private key for controller. `openssl` is optional for lab certificate generation. For Linux agent: `python3 -m pip install keyring` and configure OS keyring.

## 1. Run controller (Windows PowerShell)
From `endpoint` directory:

```powershell
$env:ZTNSS_ENROLLMENT_SECRET = '<generate-a-strong-random-secret>'
$env:ZTNSS_VIEWER_TOKEN = '<generate-a-different-strong-random-secret>'
python controller.py --bind 127.0.0.1 --port 8443 --cert server.crt --key server.key
```

Use a TLS certificate whose hostname matches the controller URL and is trusted by Windows/Python and Java. **Do not disable TLS verification.** For a two-computer LAN lab, bind to the controller's LAN IP, use a trusted certificate valid for that hostname and restrict firewall access to enrolled machines. Do not expose this educational controller to the public Internet.

## 2. Enroll and report on the authorized endpoint

```powershell
$env:ZTNSS_ENROLLMENT_SECRET = '<same-enrollment-secret>'
python agent.py --controller https://your-controller-hostname:8443 --enroll
python agent.py --controller https://your-controller-hostname:8443 --report
```

For Windows localhost testing, a certificate for `localhost` can be used with `https://localhost:8443` if its issuing CA is trusted. The agent performs **one report per invocation**. You may configure Windows Task Scheduler for periodic reporting after consent; it is not silently installed as a background service.

## 3. Run your Java Swing app
Double-click `RUN_ZTNSS.bat` or compile manually:

```bat
javac -encoding UTF-8 -d out src\main\java\com\ztnss\ZTNSSApp.java
java -cp out com.ztnss.ZTNSSApp
```

Open **Live Endpoints** in the left sidebar. Enter HTTPS controller URL and `ZTNSS_VIEWER_TOKEN`, then click **REFRESH LIVE DEVICES**. Java uses its normal TLS trust store. If using a private CA, import it into the JDK trust store safely.

## Security / interpretation
- `filtered` Nmap state is consistent with dropped packets, but does not prove firewall health. A `closed` RST response does not prove no firewall.
- Open ports are exposed services, not proof of malware.
- Agent does **not** accept remote commands or scan targets. Only install and enroll on devices with owner/administrator authorization.
- `needs_review` means evidence collected, not compliant. `unknown` means no reliable conclusion. The prototype does not auto-score or quarantine endpoints.
- Linux `lsblk` alone does not prove LUKS encryption; package timestamps are not patch compliance. Windows `Get-HotFix` is not an exhaustive update inventory. AV cmdlets may be unavailable for third-party EDR.
- Process names and open listeners are indicators for investigation, not rootkit/malware verdicts.
- Controller stores raw evidence, which can contain usernames, process names and IPs. Protect SQLite DB and set a data retention policy. Nonces older than 24 hours are cleaned during successful reporting; reports and audit events are not automatically purged.
- Controller enrollment secret is shared; restrict its use and rotate it. Device revocation currently requires deleting device enrollment via authorized DB administration and is not exposed as an API.
- Optional AbuseIPDB integration is **not implemented**; never embed API keys in source code.
- This does not implement real packet capture or TCP/UDP throughput charts. Those require Npcap/pcap integration; no fake packet counters are displayed.

## Tests and demo
1. Compile Swing app and Python files.
2. Launch controller with a trusted certificate.
3. Enroll a Windows test endpoint, submit report.
4. Confirm device appears in Live Endpoints.
5. Invalid viewer token -> HTTP 401; report signature mismatch -> HTTP 401; repeated nonce -> HTTP 409.
6. Stop controller -> UI reports connection failure, not a fabricated healthy status.
7. Compare `unknown` checks against permissions and installed tools.
8. Verify existing Nmap scan and audit tabs still work on authorized targets.

## Dashboard improvements in this package
- Added **actual Nmap port distribution** bar chart (open/closed/filtered). It updates after completed scans and displays zero before a scan, rather than fabricated data.
- Fixed the dashboard's reused Swing label problem that caused empty metric cards.
- The chart is **not packet-flow monitoring**. Genuine packet-throughput monitoring remains a future Npcap/pcap integration.

## Local validation performed during build
- `javac` Java 21 compilation: PASS.
- Python syntax compilation: PASS.
- Python protocol unit tests: 2 PASS.
- Local TLS controller integration test with a temporary trusted test certificate: PASS for enrollment, unauthorized access, report HMAC, replay rejection, inventory retrieval and audit API.
- Windows Defender, BitLocker, Windows DPAPI, Linux OS keyring and live Windows Swing appearance: **not tested in this Linux build environment**. Test these on the intended Windows machine before final presentation.
