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

**Classification:** True Positive - Malicious  
**Action Taken:** Recommended isolating WS-Prod-02, blocking the source IP 212.8.243.56, resetting the affected user credentials, and escalating the incident for further investigation.  
**Time to Triage:** 34 minutes
----------------------------------------------------------------------------------------------------------------
## Alert #2
