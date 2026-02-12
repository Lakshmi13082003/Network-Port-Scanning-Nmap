# Network Port Scanning & Service Analysis

📌 Objective

The objective of this task is to perform network reconnaissance by scanning the local network for open ports, identifying running services, and analyzing potential security risks associated with exposed services.

🛠 Tools Used

Nmap – For TCP SYN port scanning

Wireshark – For packet-level traffic analysis

Kali Linux – Testing environment

🌐 Network Information

Local IP Address: 192.168.1.226

Network Range: 192.168.1.0/24

Scan Type: TCP SYN Scan (-sS)

Command used:

nmap -sS 192.168.1.0/24

🖥 Hosts Discovered

Total Hosts Up: 5

🔹 192.168.1.1

Open Ports:

21 (FTP)

53 (DNS)

80 (HTTP)

443 (HTTPS)

🔹 192.168.1.3

Open Ports:

8008 (HTTP-alt)

8009 (AJP13)

8443 (HTTPS-alt)

9000 (cslistener)

9080 (glrpc)

🔹 192.168.1.5

Open Ports:

135 (MSRPC)

139 (NetBIOS)

445 (SMB)

🚨 Security Risk Analysis
Port 21 – FTP

Transmits credentials in plain text

Vulnerable to sniffing and brute-force attacks

Port 53 – DNS

Risk of DNS spoofing

DNS amplification attacks

Port 80 – HTTP

No encryption

Vulnerable to XSS, SQL injection

Port 443 – HTTPS

Risk if weak SSL/TLS configuration

Port 8009 – AJP13

Vulnerable to Ghostcat (CVE-2020-1938)

File read exposure risk

Port 445 – SMB (High Risk)

Exploited in WannaCry ransomware

Vulnerable to EternalBlue

Remote code execution risk

📡 Wireshark Analysis

Wireshark was used to monitor traffic during the Nmap scan.

Observed:

TCP SYN packets sent to multiple hosts

SYN-ACK responses from open ports

RST responses from closed ports

Clear-text HTTP traffic

Wireshark complements Nmap by:

Verifying scan results

Inspecting packet-level details

Identifying unencrypted communication

Packet Analysis

🛡 Recommended Security Measures

Disable unused ports

Block SMB (445) from internet

Replace FTP with SFTP

Configure firewall rules

Keep services updated and patched

✅ Outcome

This task provided hands-on experience in:

Discovering exposed services

Understanding real-world network risks

Performing basic security assessment

