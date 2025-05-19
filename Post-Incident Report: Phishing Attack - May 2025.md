# Post-Incident Report  
**Incident Title:** Phishing Email Compromise Targeting Finance Department  
**Date of Incident:** May 10, 2025  
**Date Reported:** April 10, 2025  
**Report Prepared By:** Abbas Raza  
**Role:** Cybersecurity Analyst – ArzSec Cyber Consulting  

---

## 1. Executive Summary  
On May 10, 2025, a phishing email targeting the Finance Department was detected by the organization’s email security gateway. The email impersonated a trusted vendor and prompted the recipient to download a malicious PDF containing a credential harvesting link. One user interacted with the link and entered their Office 365 credentials. Rapid detection and incident response actions prevented lateral movement and minimized the impact.

---

## 2. Incident Timeline

| Time (CST)   | Event Description                                      |
|--------------|-------------------------------------------------------|
| 09:15 AM     | Malicious email received by finance employee.         |
| 09:18 AM     | User clicked the link and submitted credentials.      |
| 09:25 AM     | User reported the email to IT.                          |
| 09:28 AM     | SOC team received alert via Microsoft Defender for Office 365. |
| 09:30 AM     | Account flagged and forced password reset initiated.  |
| 09:35 AM     | Full mailbox audit and sign-in log review commenced.  |
| 10:00 AM     | No evidence of lateral movement found.                 |
| 11:15 AM     | Domain blocked in email gateway and firewall.          |
| 01:30 PM     | Awareness email sent to all staff regarding phishing tactics. |

---

## 3. Technical Analysis  

- **Attack Vector:** Email-based phishing  
- **Sender Address:** `invoice@vendortech-secure[.]com`  
- **Subject Line:** “Invoice #88339 – Due Immediately”  
- **Payload:** Embedded PDF with a redirect to `https://vendortech-login[.]webflow[.]io`  
- **Credential Harvesting Page:** Spoofed Microsoft 365 login portal  
- **Initial Victim:** finance_user@company.com  
- **Security Tools Involved:**  
  - Microsoft Defender for Office 365  
  - Splunk SIEM  
  - SentinelOne EDR  
  - Mimecast Email Security  

---

## 4. Root Cause

The user did not verify the legitimacy of the sender and proceeded to interact with the phishing link. Although email security systems flagged the email with a suspicious score, it bypassed quarantine due to a domain trust rule configured for vendor-like domains.

---

## 5. Impact Assessment

- **Accounts Compromised:** 1 (credentials reset within 15 minutes)  
- **Data Exfiltration:** No evidence found  
- **Systems Affected:** None  
- **Business Disruption:** Minimal (limited to one user)  
- **Cost:** None incurred  

---

## 6. Mitigation & Response Actions

- Forced password reset and 2FA re-enrollment for affected user.  
- Reviewed sign-in activity logs for anomalies (none found).  
- Blocked malicious domain and IP addresses at the email gateway and firewall.  
- Implemented stricter domain trust policies.  
- Added the spoofed domain to Microsoft Defender’s block list.  
- Deployed a custom detection rule in Splunk for similar phishing URLs.  

---

## 7. Lessons Learned

- Domain trust policies need regular review and validation.  
- Awareness training is effective – user reported the email quickly.  
- Continuous tuning of email filters and SIEM alerts improves response time.  

---

## 8. Recommendations

1. Conduct phishing simulation tests quarterly.  
2. Review and tighten domain trust exceptions in the email gateway.  
3. Improve phishing awareness training with examples of recent threats.  
4. Enable conditional access policies for high-risk logins.  
5. Expand use of AI-based phishing detection tools.

---

**Incident Closed:** May 10, 2025 at 2:45 PM CST  
**Reviewed By:** Lead Security Analyst, ArzSec Cyber Consulting  
