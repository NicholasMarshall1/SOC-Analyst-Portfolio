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

**Analysis:**

* The trigger reason states that EDR-Freeze executed after suspicious PowerShell activity.
* The network activity occurred during the same time-frame as the repeated PowerShell command executions, including connections to mulitple external IP addresses.
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
* The msedge.dll was created in C:\Users\LetsDefend\AppData\Local\Temp.
* The action was Allowed, which indicates that the suspiscious activity was not blocked.
* The malicious msedge.dll artifact was located on the endpoint during the eradication phase.

**Analysis:**

* The alert indicated that archive extraction placed files in the Startup and Temp directories, which is consistent with the exploitation of CVE-2025-8088.
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
* cmd.exe executed commands that referenced a external payload from the IP 107.191.58.76.
* The same external IP appeared in both the SharePoint request and subsequent payload-related activity.

**Analysis:**

* The HTTP response code was 200 which indicates that the request was succesfully processed.

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

**Analysis:**

* No evidence was found that the activity was benign or part of an authorized test.

**Classification:** True Positive - Malicious

**Action Taken:** Isolating Victor immedietly was the first step, and then removing the malicious "service-installer" file. We then would need to block all access from the malicious source IP, and escalate this incident for further investigation if the issue persists.

**Time to Triage:** 24 Minutes

---

## Alert #5

**Date:** 2024-06-10
**Alert Title:** SOC291 - System Time Lookup Detected
**Severity:** Low
**Source IP:** 37.19.221.238
**Target:** Campbell (172.16.17.213)

**Hypothesis:** A malicious external threat actor sucessfully gained access to the user Campbells (172.16.17.213) endpoint by use of RDP brute-force attacks, the malicious actor then used system discovery commands after logging into the device.

**Evidence:**

* Multiple failed RDP login attempts that came from the external IP 37.19.221.238 against user Campbell (172.16.17.213) on port 3389.
* The failed login attempts were targeted towards multiple usernames, including test, guest, root, and LetsDefend.
* A successful RDP logon (Event ID 4624, Logon Type 10) occurred after the failed login attempts.
* After the successful RDP login, cmd.exe was created on the affected endpoint.
* Event ID 4688 logs showed cmd.exe launching HOSTNAME.EXE with the hostname command.
* Event ID 4688 logs also showed cmd.exe launching net.exe using the command net time \EC2AMAZ-ILGVOIN.
* The source IP 37.19.221.238 was flagged by external malware analysis tools as malicious.

**Analysis:**

* The net time command was used to query system information, such as time, indicating a System Time Discovery activity.
* The initial alert trigger was identified as a possible System Time Discovery attempt.
* Post-login discovery activity occurred shortly after the successful RDP authentication, this supports that the brute-force attack resulted in unauthorized access to Campbells endpoint.

**Classification:** True Positive - Malicious

**Action Taken:** Isolated Campbells endpoint, blocking the source IP 37.19.221.238, resetting the affected user credentials, reviewing the endpoint for additional activity, if more is found then we need to escalate this for further investigation.

**Time to Triage:** 14 Minutes

---

## Alert #6

**Date:** 2025-03-06
**Alert Title:** SOC337 - Lazarus Phishing Campaign Detected (APT38)
**Severity:** High
**Source:** trevorgreer9312@gmail.com
**Target:** Ellen@letsdefend.io

**Hypothesis:** A malicious phishing email impersonating a Coinbase hiring assessment was sent to Ellen in an attempt to convince the user to interact with malicious content.

**Evidence:**

* A suspicious email was sent from trevorgreer9312@gmail.com to the user Ellen@letsdefend.io. 
* The suspicious email subject was "Invitation: Coinbase Crypto Trader Hiring Assessment", and also had multiple suspicious attachments and links. 
* The sender used a Gmail address instead of an official Coinbase email domain.
* The email security action was Allowed, meaning the message was delivered to the recipient.
* The alert was identified as part of a Lazarus phishing campaign associated with APT38.
* The email download/header analysis function returned an AccessDenied error, so the email headers could not be fully verified from the downloaded EML file.

**Analysis:**

* The email was an impersonation of a Coinbase hiring assessment and attempted to convince the recipient to continue with the assessment.
* The email contained content designed to appear like a legitimate cryptocurrency job opportunity.

**Classification:** True Positive - Malicious

**Action Taken:** We removed the phishing email from the recipient's mailbox, blocked the sender and any other associated malicious indicators, determined whether Ellen interacted with the email content, and investigated the affected endpoint for any follow-on activity.

**Time to Triage:** 11 Minutes

---

## Alert #7

**Date:** 2024-09-24
**Alert Title:** SOC325 - Unauthorized Cloud Region Access Attempt Detected
**Severity:** Low
**Source IP:** 134.209.145.73
**Target:** 52.15.206.21 / test@letsdefend.io

**Hypothesis:** A malicious external actor attempted to gain unauthorized access to the target account from a restricted or unsupported cloud region.

**Evidence:**

* Multiple POST requests were made to /accounts/login from the external IP 134.209.145.73.
* The repeated access attempts targeted the user test@letsdefend.io
* Firewall logs showed the incoming connections were blocked.
* No successful HTTP 200 response or Allowed action was observed from the source IP.
* The source IP was reported by VirusTotal and AbuseIPDB in categories including malicious activity, brute force, SSH, and phishing.
* Log Management showed that only 52.15.206.21 was targeted by the attacker IP, with no evidence that additional systems were affected.
* Endpoint Security identified the target system as Ubuntu 20.04.02.
* The device action was Blocked, and all observed access attempts failed.

**Analysis:**

* Proxy logs returned HTTP 403 responses, indicating that the requests were denied.
* The source IP was identified as being located in India, which was configured as an unused or unsupported cloud region.
* The activity matched the Unused/Unsupported Cloud Regions defense evasion technique.

**Classification:** True Positive - Malicious

**Action Taken:** The target system did not require isolation because all observed requests were blocked by the firewall and proxy and no successful access was identified. Recommended blocking and monitoring the malicious source IP, continuing to monitor the affected account for additional login attempts, and reviewing cloud-region access restrictions for similar activity.

**Time to Triage:** 8 Minutes

---

## Alert #8 - Edit

**Date:** 2024-10-11
**Alert Title:** SOC331 - Zebrocy Malware Activity Detected (APT28)
**Severity:** Medium
**Source:** [pavlodar.news@bk.ru](mailto:pavlodar.news@bk.ru)
**Target:** Montague (172.16.17.132)

**Hypothesis:** A malicious executable delivered through a phishing email was opened by the user and executed on the Montague endpoint, resulting in Zebrocy malware activity and system discovery.

**Evidence:**

* The file hash has been flagged by third party malware analysis software as malicious
* The alert was triggered by execution of 2024 Financial Report.exe.
* The executable was launched from C:\Users\LetsDefend\Downloads\2024-financial-report\2024 Financial Report.exe.
* The alert trigger reason stated that the file hash was associated with known Zebrocy malware.
* The L1 note indicated that the application may have been delivered through email from [pavlodar.news@bk.ru](mailto:pavlodar.news@bk.ru).
* Network activity was observed on Montague around the same time as the malicious executable was running.

**Analysis:**

* 2024 Financial Report.exe was launched by explorer.exe, indicating user execution.
* The malicious executable spawned cmd.exe.
* cmd.exe executed the SYSTEMINFO command, indicating System Information Discovery.
* cmd.exe executed the TASKLIST command, indicating Process Discovery.
* The initial access method was consistent with phishing.

**Classification:** True Positive - Malicious

**Action Taken:** Recommended isolating Montague, removing 2024 Financial Report.exe and any related malicious artifacts, blocking the associated sender and indicators, reviewing the endpoint for additional persistence or command-and-control activity, and escalating the incident for further investigation.

**Time to Triage:** 14 Minutes

---

## Alert #9 - Edit

**Date:** 2025-02-04
**Alert Title:** SOC336 - Windows OLE Zero-Click RCE Exploitation Detected (CVE-2025-21298)
**Severity:** Critical
**Source:** [projectmanagement@pm.me](mailto:projectmanagement@pm.me)
**Target:** [Austin@letsdefend.io](mailto:Austin@letsdefend.io) / 172.16.17.137

**Hypothesis:** A malicious RTF attachment was delivered through email and exploited CVE-2025-21298, resulting in remote code execution and follow-on malicious activity on the affected endpoint.

**Evidence:**

* A phishing email was sent from `projectmanagement@pm.me` to `Austin@letsdefend.io`.
* The email subject was `Important: Action Required for Upcoming Project Deadline`.
* The email contained a password-protected RTF attachment named `mail.rtf`.
* The email security action was Allowed.
* The alert trigger identified the RTF attachment as matching a known CVE-2025-21298 exploit pattern.
* The attachment SHA256 hash df993d037cdb77a435d6993a37e7750dbbb16b2df64916499845b56aa9194184 was flagged as a malicious trojan by external malware analysis software.
* Endpoint telemetry showed OUTLOOK.EXE spawning cmd.exe.
* cmd.exe then spawned regsvr32.exe.
* regsvr32.exe was associated with a command referencing the remote shell.sct resource.
* Proxy logs showed the affected endpoint 172.16.17.137 making an HTTP GET request to 84.38.130.118 on port 80.
* The request targeted http://84.38.130.118.com/shell.sct.

**Analysis:**

* The proxy action was Permitted, confirming that the malicious remote address was accessed.
* The malicious activity continued after email delivery, indicating the attachment was not successfully quarantined or cleaned before execution.

**Classification:** True Positive - Malicious

**Action Taken:** Recommended isolating the affected endpoint, deleting the email from the users inbox, removing the malicious RTF and related artifacts, blocking the malicious remote infrastructure at 84.38.130.118, reviewing the host for additional persistence or payloads, and escalating the incident for further investigation.

**Time to Triage:** 23 Minutes

## Alert #10 - Edit

**Date:** 2025-03-13  
**Alert Title:** SOC338 - Lumma Stealer - DLL Side-Loading via Click Fix Phishing  
**Severity:** Critical  
**Source:** update@windows-update.site   
**Target:** dylan@letsdefend.io / 172.16.17.216  

**Hypothesis:** A phishing email redirected Dylan to a malicious website containing a ClickFix script that led to PowerShell and mshta.exe execution.

**Evidence:**

* The suspicious email with multiple attachments and links was sent on 2025-03-13 at 02:44:00.
* The SMTP sender IP was 132.232.40.201.
* The sender address was update@windows-update.site.
* The recipient address was dylan@letsdefend.io.
* The email subject was "Upgrade your system to Windows 11 Pro for FREE".
* The email security action was Allowed.
* The email contained attachments.
* The alert trigger stated that the redirected site contained a ClickFix type script for Lumma Stealer distribution.
* The URL https://windows-update[.]site/ was scanned with third-party analysis software and was flagged as malicious.
* Proxy logs showed 172.16.17.216 connecting to https://windows-update.site/ over port 443.
* The request to https://windows-update.site/ returned HTTP Status 200 OK.
* Browser History on the affected endpoint showed a visit to https://windows-update.site/ at 23:26:08
* One PowerShell command invoked mshta.exe with a URL hosted on overcoatpassably.shop

**Analysis:**

* The email characteristics, malicious URL verdict, browser activity, PowerShell execution, and mshta.exe activity support that the ClickFix execution chain progressed beyond the original phishing email.
* The endpoint activity shows a process chain of explorer.exe → powershell.exe → powershell.exe → mshta.exe.
* The investigation confirmed that the suspicious website was opened and that commands associated with the ClickFix activity were executed.
* No separate Lumma Stealer executable or DLL was directly identified during the investigation, so the evidence does not independently prove that a specific Lumma payload executed.

**Classification:** True Positive - Malicious  

**Actions Taken:** 
* The phishing email was deleted from the users inbox.
* The affected environment was contained pending further investigation.
* Additional investigation was required to determine whether the device was fully secure before containment could be lifted.

**Time to Triage:** 16 Minutes

## Alert #11 - Edit

**Date:** 2024-10-15  
**Alert Title:** SOC332 - CosmicDuke Malware Activity Detected (APT29)  
**Severity:** Medium  
**Source:** dawid.tomaszewski@resetlocations.com  
**Target:** ricky@letsdefend.io / 172.16.17.133  

**Hypothesis:** A phishing email delivered a malicious Chrome update archive to Ricky, which was extracted and executed on the endpoint.

**Evidence:**

* The alert was triggered by Chrome_updates.exe.
* The alert stated that the hash was associated with CosmicDuke malware.
* The SHA256 hash b5c571cbe24b37359eb4018bac19e37a2ffc6108d6d1cb5c8c22640397c47596 was flagged as malicious by third-party analysis.
* An email was sent from dawid.tomaszewski@resetlocations.com to ricky@letsdefend.io.
* The email subject was "Urgent: Chrome Security Update - Action Required".
* The email security action was Allowed.
* The email contained the attachment chrome-updates.zip.
* The email instructed the recipient to download and run the attached Chrome update.
* The extracted chrome-updates folder was present in Ricky's Downloads directory.
* The Chrome_updates` application was present inside the extracted folder.
* Log Management showed a file creation event for Chrome_updates.exe.
* Log Management showed an Event ID 1 Process Create event for Chrome_updates.exe.
* Searches for the sender email and sender IP only showed activity associated with Ricky.
* No evidence of the malicious IOC appearing on more than one endpoint was observed.
* The malicious executable was still present on Ricky's computer during the investigation.
* No evidence of the file being quarantined or cleaned was observed.
* The playbook showed that Chrome_updates.exe attempted C2-related activity but crashed before successful communication occurred.

**Analysis:**

* The suspicious email, attached archive, extracted executable, and process creation event support phishing as the initial access method.
* The Process Create event confirms that Chrome_updates.exe was executed on Ricky's endpoint.
* The investigation only identified the malicious activity on Ricky's endpoint.
* The malware attempted C2-related activity, but successful C2 communication was not confirmed because the application crashed before communication was completed.

**Classification:** True Positive - Malicious  

**Actions Taken:**

* The affected host was contained.
* The malicious Chrome_updates.exe file was deleted from the affected hosts endpoint.

**Time to Triage:** 18 Minutes

## Alert #12 - Edit 

**Date:** 2025-03-20  
**Alert Title:** SOC339 - ZDI-CAN-25373 Windows Shortcut Exploit Detected  
**Severity:** High  
**Source:** michael.johnson@pm.me  
**Target:** Cooper@letsdefend.io / 172.16.17.217  

**Hypothesis:** A phishing email delivered a malicious shortcut file to Cooper, which was opened and triggered PowerShell activity that connected to an external IP address.

**Evidence:**

* The hash 6F927D74FB2075C60F2F7795B718CA571947F3D1E7B591D2D2FD5A35DD5503F8 was flagged as malicious by third-party analysis and identified as a Trojan.PowerShell / Trojan downloader.
* A suspicious email was sent from Michael.johnson@pm.me to Cooper@letsdefend.io.
* The malicious files 2025annualreport.7z and 2025AnnualReport were present in the Downloads directory on Cooper's device.
* The malware had not been cleaned or quarantined because the malicious files were still present on the device.
* The malicious shortcut activity triggered powershell.exe.
* PowerShell executed a command that referenced http://18.223.186.129:4444/MBS.ps1.
* Sysmon Event ID 3 showed powershell.exe on 172.16.17.217 making a TCP connection to 18.223.186.129 on port 4444.
* The destination IP was 18.223.186.129.
* The destination port was 4444.
* The protocol was TCP.
* The process responsible for the connection was powershell.exe.
* The UserHostIp was 172.16.17.217.

**Analysis:**

* The suspicious email and malicious files found in Cooper's Downloads directory support phishing as the initial access method.
* The execution of PowerShell after the malicious shortcut was opened supports both User Execution and Command and Scripting Interpreter activity.
* The PowerShell command attempted to retrieve and execute a remote PowerShell script from 18.223.186.129:4444.
* The Sysmon Event ID 3 network event confirms that Cooper's endpoint made a TCP connection to the external address used by the malicious PowerShell command.
* The evidence supports that the malicious activity progressed beyond the initial phishing email and resulted in execution and external network communication.

**Classification:** True Positive - Malicious  

**Actions Taken:**

* The affected endpoint was isolated.
* The malware was eradicated from the device.
* The phishing email was deleted.

**Time to Triage:** 16 Minutes
