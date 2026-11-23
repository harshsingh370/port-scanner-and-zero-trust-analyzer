# ZTNSS Pro — Cyber Guardian (Java Swing)

## Visual refresh
The interface now uses a consistent dark navy / slate / gold security-console theme. The duplicate top tab strip is hidden (navigation is through the left sidebar), page content expands to the available width, and text areas, scroll panes, tables, inputs and dialogs use dark colors to avoid the white-background rendering bug in the supplied screenshot.

## Modules
- **Dashboard:** Nmap readiness, open/closed/filtered counts, device posture and findings.
- **IP Scanner:** Nmap TCP connect scan (`-sT -sV`) for one authorized IPv4 target; top 100 / top 1000 / common web ports / custom ports.
- **Port Analysis:** Select a discovered row to see the port's service name, what it does, why an exposed service matters, possible consequences if misconfigured, risk rating and mitigation.
- **Firewall:** Explains open / closed / filtered packet responses and queries the local Windows Defender Firewall or Linux UFW/nftables where available.
- **Device Health:** Reports local hostname, user, local IP, MAC, OS and firewall baseline. It clearly lists posture checks that still need an authenticated endpoint agent.
- **Audit Logs:** Timestamp, local hostname/IP, OS user, action, target IP and details; CSV export.

## Open port interpretation
An open port means a process accepted a connection. It is an exposed service, not proof of malware or compromise. Risk depends on service, version, configuration, credentials and network exposure. The UI provides specific explanations for common services including FTP, SSH, Telnet, SMTP, DNS, HTTP/HTTPS, SMB, MySQL, RDP, PostgreSQL, VNC and alternate web ports.

## Firewall interpretation
- **Filtered:** no definitive response / timeout. Consistent with silent packet dropping, but can also result from routing issues, packet loss or a down host.
- **Closed:** host responded (often TCP RST / ICMP unreachable) and no application is listening. This does not prove there is no firewall; a firewall may actively reject traffic.
- **Open:** a service accepted the TCP connection.

The local firewall check is an endpoint configuration check, distinct from remote packet-response observations. It is not a guarantee of complete firewall correctness.

## Requirements and run instructions
- JDK 17+ (JDK 21 recommended)
- Nmap installed and available in PATH: https://nmap.org/download.html
- Windows: extract ZIP and double-click `RUN_ZTNSS.bat`.
- Linux/macOS: compile with `javac -encoding UTF-8 -d out src/main/java/com/ztnss/ZTNSSApp.java`, then run `java -cp out com.ztnss.ZTNSSApp`.

## Device posture limitations
The current build performs local identity and firewall checks. OS patch age, AV/EDR definition freshness, BitLocker/LUKS/FileVault, suspicious processes, local administrator review on remote hosts and IP reputation require additional OS-specific checks, API credentials or an authenticated endpoint agent. Nmap cannot verify these properties on its own.

## Safety
Only scan devices you own or have explicit authorization to assess. This academic project is not an enterprise EDR, NAC or production firewall enforcement platform.
