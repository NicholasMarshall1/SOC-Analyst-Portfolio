## Alert #1
**Date:** 2025-09-26  
**Alert Title:** SOC344 - EDR Tampering Attempt via EDR-Freeze  
**Severity:** High  
**Source IP:** 212.8.243.56  
**Target:** WS-Prod-02  

**Hypothesis:** Possible attacker activity involving unauthorized RDP access, followed by PowerShell activity and execution of an EDR tampering tool.

**Evidence:**
- EDR-Freeze_1.0.exe was executed on WS-Prod-02.
- The parent process was powershell.exe.
- The device action was Allowed.
- The trigger reason states that EDR-Freeze executed after suspicious PowerShell activity.
- EDR-Freeze_1.0.exe spawned WerFaultSecure.exe.
- Terminal history shows repeated PowerShell executions between approximately 13:01 and 13:03 on WS-Prod-02.
- Network activity occurred during the same time frame as the repeated PowerShell executions, including connections to several external IP addresses.
- LetsDefend Threat Intel returned no results for the observed external IP addresses or the EDR-Freeze SHA256 hash.
- Multiple failed RDP login attempts originated from 212.8.243.56 against WS-Prod-02.
- The failed attempts targeted multiple usernames, including admin and LetsDefend.
- A successful RDP logon (Event ID 4624, Logon Type 10) occurred shortly after the failed attempts from the same source IP.

Classification: True Positive - Malicious  
Action Taken: Recommended isolating WS-Prod-02, blocking the source IP 212.8.243.56, resetting the affected user credentials, and escalating the incident for further investigation.  
Time to Triage: 34 minutes

## Alert #2
**Date:** 2025-08-15
**Alert Title:** SOC343 - WinRAR Zero-Day Path Traversal Vulnerability
**Severity:** Critical
**Source:** Phishing email from an external sender
**Target:** Stweart (172.16.17.183)

**Hypothesis:** A phishing email that contained a malicious attachment was opened by the user (Stewart) and then exploited a WinRaR vulnerability to create malicious files on the endpoint. 

**Evidence:**
- A suspisious email with a CV attachment was delivered to stewart@letsdefend.io and was allowed by the email security system.
- The L1 note stated that the suspicious file creation had occured in Temp and Startup locations after the user executed the email attachment.
- WinRar.exe was used to extract the archive associated with the suspicious attachment.
- The alert indicated that archive extraction placed files in the Startup and Temp directories, which is consistent with the exploitation of CVE-2025-8088.
- The msedge.dll was created in C:\Users\LetsDefend\AppData\Local\Temp.
- The action was Allowed, which indicates that the suspiscious activity was not blocked.
- The malicious msedge.dll artifact was located on the endpoint during the eradication phase.

Classification: True Positive - Malicious - Successful Phishing Attack
Action Taken: Isolated the device and the infected endpoint was investigated for the malicious file msedge.dll. The file was found and deleted. 
Time to Triage: 32 Minutes

