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
* Terminal history shows repeated PowerShell executions between approximately 13:01 and 13:03 on WS-Prod-02.
* Network activity occurred during the same time frame as the repeated PowerShell executions, including connections to several external IP addresses.
* LetsDefend Threat Intel returned no results for the observed external IP addresses or the EDR-Freeze SHA256 hash.
* Multiple failed RDP login attempts originated from 212.8.243.56 against WS-Prod-02.
* The failed attempts targeted multiple usernames, including admin and LetsDefend.
* A successful RDP logon (Event ID 4624, Logon Type 10) occurred shortly after the failed attempts from the same source IP.

**Classification:** True Positive - Malicious

**Action Taken:** Recommended isolating WS-Prod-02, blocking the source IP 212.8.243.56, resetting the affected user credentials, and escalating the incident for further investigation.

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
* The malware was downloaded from https://files-ld.s3.us-east-2.amazonaws.com/service-installer.zip.
* Log analysis confirmed that the malware-hosting/C2 infrastructure was accessed and the malicious archive was downloaded.
* The malware was successfully executed on the endpoint.
* No evidence was found that the activity was benign or part of an authorized test.

**Classification:** True Positive - Malicious

**Action Taken:** Isolating Victor immedietly was the first step, and then removing the malicious "service-installer" file. We then would need to block all access from the malicious source IP, and escalate this incident for further investigation if the issue persists. 

**Time to Triage:** 24 Minutes
