## Alert #1

**Date:** 2025-09-26
**Alert Title:** SOC344 - EDR Tampering Attempt via EDR-Freeze
**Severity:** High
**Source IP:** 212.8.243.56
**Target:** WS-Prod-02

**Hypothesis:** Possible attacker activity involving unauthorized RDP access, followed by PowerShell activity and execution of an EDR tampering tool.

**Evidence:**

* EDR-Freeze_1.0.exe was executed on WS-Prod-02.
* The parent process was powershell.exe.
* The device action was Allowed.
* The trigger reason states that EDR-Freeze executed after suspicious PowerShell activity.
* EDR-Freeze_1.0.exe spawned WerFaultSecure.exe.
* The terminal history had shown repeated PowerShell command executions between approximately 13:01 and 13:03 on the WS-Prod-02 endpoint.
* The network activity occurred during the same time-frame as the repeated PowerShell command executions, including connections to mulitple external IP addresses.
* LetsDefend Threat Intel returned no results for the observed external IP addresses or the EDR-Freeze SHA256 hash.
* Multiple failed RDP login attempts originated from 212.8.243.56 against WS-Prod-02.
* The failed attempts targeted multiple usernames, including admin and LetsDefend.
* A successful RDP logon (Event ID 4624, Logon Type 10) occurred shortly after the failed attempts from the same source IP.

**Classification:** True Positive - Malicious

**Action Taken:** Recommended isolating the WS-Prod-02 endpoint, blocking the source IP 212.8.243.56, resetting the affected user credentials, and escalating the incident for further investigation.

**Time to Triage:** 34 minutes

---

## Alert #2

**Date:** 2025-08-15
**Alert Title:** SOC343 - WinRAR Zero-Day Path Traversal Vulnerability
**Severity:** Critical
**Source IP:** N/A - Phishing email
**Target:** Stewart (172.16.17.183)

**Hypothesis:** A phishing email that contained a malicious attachment was opened by the user (Stewart) and then exploited a WinRaR vulnerability to create malicious files on the endpoint.

**Evidence:**

* A suspisious email with a CV attachment was delivered to [stewart@letsdefend.io](mailto:stewart@letsdefend.io) and was allowed by the email security system.
* The L1 note stated that the suspicious file creation had occured in Temp and Startup locations after the user executed the email attachment.
* WinRar.exe was used to extract the archive associated with the suspicious attachment.
* The alert indicated that archive extraction placed files in the Startup and Temp directories, which is consistent with the exploitation of CVE-2025-8088.
* The msedge.dll was created in C:\Users\LetsDefend\AppData\Local\Temp.
* The action was Allowed, which indicates that the suspiscious activity was not blocked.
* The malicious msedge.dll artifact was located on the endpoint during the eradication phase.
* Successful Phishing Attack - Phishing email from an external sender.

**Classification:** True Positive - Malicious

**Action Taken:** Isolated the device and the infected endpoint was investigated for the malicious file msedge.dll. The file was found and deleted.

**Time to Triage:** 32 Minutes

---

## Alert #3

**Date:** 2025-07-22
**Alert Title:** SOC342 - CVE-2025-53770 SharePoint ToolShell Auth Bypass and RCE
**Severity:** Critical
**Source IP:** 107.191.58.76
**Target:** SharePoint01 (172.16.20.17)

**Hypothesis:** Attacker executed code on the server remotely using the known SharePoint vulnerability (CVE-2025-53770).

**Evidence:**

* An unauthenticated HTTPS POST request was sent from the external IP 107.191.58.76 to SharePoint01 (172.16.20.17) on port 443.
* The request targeted The request targeted '/_layouts/15/ToolPane.aspx' which is the SharePoint application page/path.
* The HTTP response code was 200 which indicates that the request was succesfully processed.
* cmd.exe executed commands that referenced a external payload from the IP 107.191.58.76.
* The same external IP appeared in both the SharePoint request and subsequent payload-related activity.

**Classification:** True Positive - Malicious

**Action Taken:** Escalated to Tier 2 for incident response, and need to isolate SharePoint01 and block the IP 107.191.58.76. The malicious payloads need to be removed to prevent more damage. Finally SharePoint needs to be mitigated and isolated until the proper security update comes out and the patch can be applied.

**Time to Triage:** 22 Minutes

---

## Alert #4

**Date:** 2025-01-22
**Alert Title:** SOC335 - CVE-2024-49138 Exploitation Detected
**Severity:** Medium
**Source IP:** 185.107.56.141
**Target:** Victor (172.16.17.207)

**Hypothesis:** A malicious external threat actor exploited the endpoint by delivering a trojan virus, that was executed through PowerShell that exploited the system

**Evidence:**

* The file hash associated with the alert was identified as malicious and classified as a trojan by external malware analysis tools.
* The alert trigger stated that suspicious behavior associated with the malicious hash was identified and was consistent with exploitation of CVE-2024-49138.
* Log Management showed traffic from the external IP 185.107.56.141 to the affected endpoint 172.16.17.207.
* The malware was downloaded from a infected installer https://files-ld.s3.us-east-2.amazonaws.com/service-installer.zip.
* Log analysis confirmed that the malware-hosting/C2 infrastructure was accessed and the malicious archive was downloaded.
* The malware was successfully executed on the endpoint.
* No evidence was found that the activity was benign or part of an authorized test.

**Classification:** True Positive - Malicious

**Action Taken:** Isolating Victor immedietly was the first step, and then removing the malicious "service-installer" file. We then would need to block all access from the malicious source IP, and escalate this incident for further investigation if the issue persists. 

**Time to Triage:** 24 Minutes

## Alert #5

**Date:** 2024-06-10
**Alert Title:** SOC291 - System Time Lookup Detected
**Severity:** Low
**Source IP:** 37.19.221.238
**Target:** Campbell (172.16.17.213)

**Hypothesis:** A malicious external threat actor sucessfully gained access to the user Campbells (172.16.17.213) endpoint by use of RDP brute-force attacks, the malicious actor then used system discovery commands after logging into the device. 

**Evidence:**

- Multiple failed RDP login attempts that came from the external IP 37.19.221.238 against user Campbell (172.16.17.213) on port 3389.
- The failed login attempts were targeted towards multiple usernames, including test, guest, root, and LetsDefend.
- A successful RDP logon (Event ID 4624, Logon Type 10) occurred after the failed login attempts.
- After the successful RDP login, cmd.exe was created on the affected endpoint.
- Event ID 4688 logs showed cmd.exe launching HOSTNAME.EXE with the hostname command.
- Event ID 4688 logs also showed cmd.exe launching net.exe using the command net time \\EC2AMAZ-ILGVOIN.
- The net time command was used to query system information, such as time, indicating a System Time Discovery activity.
- The initial alert trigger was identified as a possible System Time Discovery attempt.
- Post-login discovery activity occurred shortly after the successful RDP authentication, this supports that the brute-force attack resulted in unauthorized access to Campbells endpoint.
- The source IP 37.19.221.238 was flagged by external malware analysis tools as malicious. 

**Classification:** True Positive - Malicious

**Action Taken:** Isolated Campbells endpoint, blocking the source IP 37.19.221.238, resetting the affected user credentials, reviewing the endpoint for additional activity, if more is found then we need to escalate this for further investigation.

**Time to Triage:** 14 Minutes

## Alert #6

**Date:** 2025-03-06
**Alert Title:** SOC337 - Lazarus Phishing Campaign Detected (APT38)
**Severity:** High
**Source:** trevorgreer9312@gmail.com
**Target:** Ellen@letsdefend.io

**Hypothesis:** A malicious phishing email impersonating a Coinbase hiring assessment was sent to Ellen in an attempt to convince the user to interact with malicious content.

**Evidence:**

* A suspicious email was sent from trevorgreer9312@gmail.com to Ellen@letsdefend.io. 
* The email subject was "Invitation: Coinbase Crypto Trader Hiring Assessment."
* The email impersonated a Coinbase hiring assessment and attempted to convince the recipient to continue with the assessment.
* The sender used a Gmail address instead of an official Coinbase email domain.
* The email security action was Allowed, meaning the message was delivered to the recipient.
* The alert was identified as part of a Lazarus phishing campaign associated with APT38.
* The email contained content designed to appear like a legitimate cryptocurrency job opportunity.
* The email download/header analysis function returned an AccessDenied error, so the email headers could not be fully verified from the downloaded EML file.

**Classification:** True Positive - Malicious

**Action Taken:** Recommended removing the phishing email from the recipient's mailbox, blocking the sender and any associated malicious indicators, determining whether Ellen interacted with the email content, and investigating the affected endpoint for any follow-on activity.

**Time to Triage:** 11 Minutes

## Alert #7

**Date:** 2024-09-24
**Alert Title:** SOC325 - Unauthorized Cloud Region Access Attempt Detected
**Severity:** Low
**Source IP:** 134.209.145.73
**Target:** 52.15.206.21 / [test@letsdefend.io](mailto:test@letsdefend.io)

**Hypothesis:** A malicious external actor attempted repeated unauthorized access against the target account from a restricted or unsupported cloud region.

**Evidence:**

* Multiple POST requests were made to /accounts/login from the external IP 134.209.145.73.
* The repeated access attempts targeted the user test@letsdefend.io.
* Firewall logs showed the incoming connections were blocked.
* Proxy logs returned HTTP 403 responses, indicating that the requests were denied.
* No successful HTTP 200 response or Allowed action was observed from the source IP.
* The source IP was reported by VirusTotal and AbuseIPDB in categories including malicious activity, brute force, SSH, and phishing.
* The source IP was identified as being located in India, which was configured as an unused or unsupported cloud region.
* The activity matched the Unused/Unsupported Cloud Regions defense evasion technique.
* Log Management showed that only 52.15.206.21 was targeted by the attacker IP, with no evidence that additional systems were affected.
* Endpoint Security identified the target system as Ubuntu 20.04.02.
* The device action was Blocked, and all observed access attempts failed.

**Classification:** True Positive - Malicious

**Action Taken:** The target system did not require isolation because all observed requests were blocked by the firewall and proxy and no successful access was identified. Recommended blocking and monitoring the malicious source IP, continuing to monitor the affected account for additional login attempts, and reviewing cloud-region access restrictions for similar activity.

**Time to Triage:** 8 Minutes

## Alert #8

**Date:** 2024-10-11
**Alert Title:** SOC331 - Zebrocy Malware Activity Detected (APT28)
**Severity:** High
**Source:** [pavlodar.news@bk.ru](mailto:pavlodar.news@bk.ru)
**Target:** Montague (172.16.17.132)

**Hypothesis:** A malicious executable delivered through a phishing email was opened by the user and executed on the Montague endpoint, resulting in Zebrocy malware activity and system discovery.

**Evidence:**

* The alert was triggered by execution of 2024 Financial Report.exe.
* The executable was launched from C:\Users\LetsDefend\Downloads\2024-financial-report\2024 Financial Report.exe.
* The alert trigger reason stated that the file hash was associated with known Zebrocy malware.
* The L1 note indicated that the application may have been delivered through email from pavlodar.news@bk.ru.
* 2024 Financial Report.exe was launched by explorer.exe, indicating user execution.
* The malicious executable spawned cmd.exe.
* cmd.exe executed the SYSTEMINFO command, indicating System Information Discovery.
* cmd.exe executed the TASKLIST command, indicating Process Discovery.
* Network activity was observed on Montague around the same time as the malicious executable was running.
* The initial access method was consistent with phishing.

**Classification:** True Positive - Malicious

**Action Taken:** Recommended isolating Montague, removing 2024 Financial Report.exe and any related malicious artifacts, blocking the associated sender and indicators, reviewing the endpoint for additional persistence or command-and-control activity, and escalating the incident for further investigation.

**Time to Triage:** 14 Minutes

