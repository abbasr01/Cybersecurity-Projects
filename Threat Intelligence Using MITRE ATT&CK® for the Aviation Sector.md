# ✈️ Threat Intelligence Using MITRE ATT&CK® for the Aviation Sector

## 🧠 Overview
This project was created as part of a **hypothetical threat intelligence (TI) exercise** to simulate the role of a Security Analyst working in the aviation sector. The scenario assumes a fictional organization transitioning to cloud infrastructure, with the objective of using the MITRE ATT&CK® framework to identify relevant APT groups and evaluate their techniques, tools, affected platforms, and mitigations.

## 🎯 Objective
Use MITRE ATT&CK® to gather **actionable cyber threat intelligence** by:
- Identifying an APT group targeting the aviation sector (active since at least 2013)
- Investigating cloud-relevant TTPs (Tactics, Techniques, Procedures)
- Exploring associated tools, affected platforms, and potential mitigations
- Highlighting any gaps in defensive coverage

## 🛠️ Tools & Resources
- [MITRE ATT&CK® Navigator](https://attack.mitre.org/)
- MITRE Threat Group and Technique documentation
- Public OSINT sources

## 📌 Scenario Summary
> You are a security analyst who works in the aviation sector. Your organization is moving their infrastructure to the cloud. Your goal is to use the ATT&CK® Matrix to gather threat intelligence on APT groups who might target this particular sector and use techniques targeting your areas of concern. You are checking to see if there are any gaps in coverage. After selecting a group, look over the selected group's information and their tactics, techniques, etc. 

---

## 🔍 Investigation Steps & Findings

### 1. 🕵️‍♂️ What is a group that targets your sector who has been in operation since at least 2013?
- APT33; APT33 is a suspected Iranian threat group that has carried out operations since at least 2013. The group has targeted organizations across multiple industries in the United States, Saudi Arabia, and South Korea, with a particular interest in the aviation and energy sectors

### 2. ☁️ As your organization is migrating to the cloud, is there anything attributed to this APT group that you should focus on?
- Yes
- APT33 is known to use the technique **Cloud Accounts (ID: T1078.004)** to maintain persistence in cloud environments.

### 3. 🧰 What tool is associated with the technique from the previous question?
- **Ruler** — APT33 has used compromised Office 365 accounts in tandem with Ruler in an attempt to gain control of endpoints.
- Ruler is a tool that exploits Outlook and Exchange Web Services (EWS) to gain remote code execution and persistence. While primarily used in on-prem environments, it remains a threat in hybrid cloud setups, where legacy Exchange components are still exposed. During cloud migrations, organizations should be cautious of tools like Ruler that can abuse outdated protocols and configurations.

### 4. 🛡️ Referring to the technique from question 2, what mitigation method suggests using SMS messages as an alternative?
- **Multi-factor Authentication (M1032)** — Recommends using out-of-band factors like **SMS-based one-time passcodes**.

### 5. 💻 What platforms does the technique from question #2 affect?
- **Affected Platforms:** `IaaS`, `Identity Provider`, `Office Suite`, `SaaS`

### 6. 🧬 What tactics are most frequently used by this APT group (APT33) according to MITRE ATT&CK®?
**- Credential Access to move laterally and escalate privileges**
  - Tools Used: LaZagne for extracting stored credentials; Mimikatz and ProcDump to dump LSASS memory for passwords, hashes, and Kerberos tickets.
  - Brute Force: They use password spraying to avoid account lockouts while testing common passwords across many accounts.

**- Execution to establish and maintain control**
  - PowerShell & VBScript: Used for post-exploitation and payload execution while blending into normal system activity.
  - Spear Phishing: Delivers malware via convincing fake job postings (e.g., .hta files) targeting aviation workers.
  - Exploits: Known to abuse vulnerabilities like CVE-2018-20250 (WinRAR) and CVE-2017-11774 (Outlook).

**- Initial Access via social engineering to breach organizations**
  - Spear Phishing: Custom emails with malicious attachments or links, often job-themed.
  - Valid Accounts: Gains access using stolen credentials—often Office 365 accounts—sometimes with tools like Ruler.

**- Persistence for long term control/benefit**
  - Registry Run Keys: Malware set to auto-launch on reboot.
  - Scheduled Tasks: Executes malicious scripts (.vbe) multiple times daily.
  - WMI Subscriptions: Triggers malware based on system events, making detection harder.

**- Command & Control**
  - Web Protocols: HTTP traffic over non-standard ports (e.g., 808, 880) to avoid detection.
  - Encryption: AES to hide command content.
  - Blending In: Using typical web traffic patterns to avoid network-based defenses.

### 7. 🧪 What detection methods are recommended for identifying the technique Valid Accounts (T1078)?
- **Logon Session Creation/Metadata:**
    - Monitor for newly constructed logon behavior that may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Correlate other security systems with login information (e.g., a user has an active login session but has not entered the building or does not have VPN access).
    - Look for suspicious account behavior across systems that share accounts, either user, admin, or service accounts. Examples: one account logged into multiple systems simultaneously; multiple accounts logged into the same machine simultaneously; accounts logged in at odd times or outside of business hours.

- **User Account Authentication:**
    - Monitor for an attempt by a user that may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. 

### 8. 🛡️ What security controls or monitoring solutions could help detect or prevent the use of Mimikatz in a cloud-enabled environment?
Encourages mapping between a known threat and real-world tooling (e.g., EDR, SIEM, identity protection solutions).
- Mimikatz is a credential dumper capable of obtaining plaintext Windows account logins and passwords, along with many other features that make it useful for testing the security of networks.  Mimikatz is known for dumping credentials from LSASS and performing pass-the-hash/ticket attacks, so the goal is to detect these behaviors and restrict conditions that enable them.
- Disable Unnecessary Local Admin Access
- LSASS (Local Security Authority Subsystem Service) Protection
    - Lsass.exe; Service that enforces the security policy and user authentication on the system.
    		- It handles tasks like verifying user logins, managing password changes, creating access tokens, and logging security-related events.
    - Enable Credential Guard (Windows Defender feature) to isolate LSASS in a secure environment, preventing tools like Mimikatz from accessing it.
- Enforce AppLocker or Microsoft Defender Application Control (MDAC) to **Block Unsigned Scripts and Binaries**, including Mimikatz variants
- Use Microsoft Defender for Endpoint, CrowdStrike, or SentinelOne with memory protection and credential dumping detection.
    - These EDR/EPP tools often have behavioral AI to flag Mimikatz-like behavior—even if obfuscated
- Azure AD/Azure Integration
    - Audit Sign-ins and detect anomalies with Azure AD Identity Protection
    - Use Defender for Identity to monitor on-prem AD hybrid infrastructure for Kerberos ticket abuse
    - Enable Conditional Access to restrict access based on device compliance and risk levels

### 9. 🧾 Has this APT group been linked to any public breaches or campaigns targeting aviation or cloud infrastructure? If so, what were the IOCs or behaviors involved?

**Aviation Sector Targeting**
1. 2016-2017 Spear Phishing Operations
    - Malicious .hta Files: APT33 sent recruitment-themed emails with links to malicious HTML application (.hta) files disguised as job postings for Saudi Arabian petrochemical and aviation companies. These files downloaded custom backdoors like TURNEUP.
    - Spoofed Domains: Used domains mimicking legitimate aviation companies (e.g., Alsalam Aircraft Company, Boeing, Northrop Grumman) to enhance credibility.
    - Exploits: Leveraged vulnerabilities such as CVE-2017-11774 (Microsoft Office) and CVE-2018-20250 (WinRAR) to execute payloads.
2. 2019 Compressed File Campaign
    - Malicious ZIP Files: Distributed archives exploiting the WinRAR vulnerability (CVE-2018-20250) to deploy malware targeting Saudi chemical companies.

Behavioral Patterns
- Spear Phishing Lures: Focused on aviation job opportunities, often referencing Saudi partnerships.
- Custom Malware: Deployed tools like DROPSHOT (linked to the SHAPESHIFT wiper) and TurnedUp backdoor.


**Cloud Infrastructure Targeting**
1. 2024 Azure-Based Campaign
    - Azure Tenant Abuse: Created attacker-controlled Azure subscriptions using hijacked educational sector accounts, establishing C2 infrastructure.
    - Tickler Malware:
        - Delivery: Distributed via .zip files masquerading as PDFs.
        - Functionality: Collected system information, executed batch scripts (e.g., reg.exe to modify registry Run keys), and leveraged AnyDesk for persistence.
        - Lateral Movement: Used SMB protocol and AD Explorer to harvest Active Directory data.
IOCs
- User Agents: go-http-client in password spray attacks.
- Registry Keys: Persistence via HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SharePoint.exe.
- Network Protocols: Non-standard ports (808, 880) for HTTP C2 traffic.

Behavioral Patterns
- Password Spraying: Targeted defense, education, and government sectors to avoid account lockouts.
- Social Engineering: Posed as students, developers, and recruiters on LinkedIn to compromise targets.


### 10. 🌐 How could threat intel like this be operationalized for your SOC or IR team?
Let’s say my SOC team reads that an attacker is using Mimikatz to dump credentials.

They could:
- Use that info to create YARA rules or EDR detections
- Add that behavior to the threat hunt playbook
- Train analysts to recognize Golden Ticket signs
- Proactively look for TGT tickets with long durations
- Watch for processes like procdump accessing lsass.exe

---

## 📈 Outcome
- Practiced using MITRE ATT&CK® to perform threat group profiling
- Mapped real-world adversary behaviors to tools and mitigations
- Highlighted how CTI can inform cloud migration defense strategies
- Strengthened understanding of attacker persistence techniques and MFA requirements

---

## 📚 What I Learned
- How to derive operational value from open-source threat intelligence
- How to align MITRE ATT&CK® techniques with evolving infrastructure needs (e.g. cloud)
- The importance of multi-layered authentication as a defensive control

---

## 💼 Use Cases
- Creating threat-informed defense strategies for specific industries
- Educating teams on attacker behaviors and risk areas
- Building CTI workflows into cloud security planning

---

## 📎 Disclaimer
This project was completed as a **hypothetical scenario for educational purposes only**. It does not reflect any real organization or event.

---

