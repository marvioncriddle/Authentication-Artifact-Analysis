# Authentication Artifact Analysis
<img align="center" width="800px" src="https://i.imgur.com/GtZorHR.png" />

## Overview

Authentication failures are among the most common indicators encountered during security monitoring. While repeated failed logins may simply result from a user forgetting a password, they may also indicate password spraying, brute-force attacks, stale credentials, or misconfigured services.

A Windows Security Event Log (Security.evtx) has been preserved from a simulated enterprise environment and provided for analysis.  Login failures were intentionally generated to create a realistic dataset for investigation, allowing you to analyze patterns and determine whether the behavior reflects normal user activity or a potential attack.

In this lab, you will investigate a Windows account lockout using native forensic artifacts found in the Windows Security Event Log. Your objective is to determine whether the observed behavior represents malicious activity or normal user behavior by correlating authentication events and documenting your findings as you would during a real-world Digital Forensics and Incident Response (DFIR) investigation.

## Scenario

A user reports that their Windows account has been repeatedly locking out throughout the day. Management has asked the security team to determine whether the lockouts were caused by normal user behavior or by an attempted brute-force attack against the account.
As the DFIR analyst assigned to the case, you have been provided with preserved authentication evidence. Your task is to analyze the available data, identify the originating system, and provide recommendations based on your findings.

## Learning Objectives

After completing this lab, you should be able to:
- Analyze Windows authentication events
- Investigate Windows account lockouts
- Interpret Security Event IDs related to authentication
- Differentiate failed and successful logon attempts
- Identify the source of authentication attempts
- Correlate multiple authentication artifacts to determine root cause
- Document investigative findings using professional DFIR methodology

## Windows Artifacts Examined

This investigation focuses on several key Windows Security events.

| <h3>Event ID</h3>	| <h3>Description</h3>       |
| ----------------- | -------------------------- |
|<p>4625</p>	      | <p>Failed logon attempt</p>|
|<p>4624</p>        | <p>Successful logon</p>    |
|<p>4740</p>        | <p>Account locked out</p>  |

Primary Evidence: Security.evtx

## Investigation Questions
During this investigation, answer the following:
- Which user accounts experienced failed authentication attempts?
- Which workstation initiated those attempts?
- Which source IP generated the authentication requests?
- Which Status and SubStatus codes were observed?
- Which account became locked?
- Which MITRE ATT&CK technique best aligns with the observed activity?
- What is the most likely root cause?


## Investigation Workflow
The investigation follows a methodology commonly used during enterprise DFIR engagements.
### Step 1: Review Evidence

You have been provided with a preserved Windows Security Event Log (Security.evtx).

Ensure you are working from this evidence file rather than a live system. Maintaining the integrity of original evidence is a fundamental forensic principle and allows investigators to revisit findings without altering the source data.

### Step 2: Triage Key Authentication Events

Filter the Security log for the key authentication-related Event IDs
```powershell
Get-WinEvent -Path .\Evidence\Security.evtx |
Where-Object {$_.Id -in 4625, 4624, 4740} |
Group-Object Id |
Sort-Object Count -Descending |
Select-Object @{Name='EventID';Expression={$_.Name}}, Count |
Format-Table -AutoSize
```
</br>
<img align="center" width="600px" src="https://i.imgur.com/GgIBjg7.png" />
</br>
</br>

### Step 3: Analyze Failed Authentication Attempts

Filter the Security log for Event ID 4625

Event ID 4625 = failed logon event:
</br>
<img align="center" width="600px" src="https://i.imgur.com/71mCTfT.png" />
</br>
</br>

Export the failed logon events to a CSV file:

```powershell
Get-WinEvent -Path .\Evidence\Security.evtx |
Where-Object {$_.Id -eq 4625} |
Select-Object `
    TimeCreated,
    @{Name='Username';Expression={$_.Properties[5].Value}},
    @{Name='Workstation';Expression={$_.Properties[13].Value}},
    @{Name='SourceIP';Expression={$_.Properties[19].Value}},
    @{Name='LogonType';Expression={$_.Properties[10].Value}},
    @{Name='Status';Expression={$_.Properties[7].Value}},
    @{Name='SubStatus';Expression={$_.Properties[9].Value}} |
Export-Csv .\Evidence\FailedLogins.csv -NoTypeInformation
```

Determine which Usernames failed to logon:
```powershell
Import-Csv .\Evidence\FailedLogins.csv | Format-Table
$events = Import-Csv .\Evidence\FailedLogins.csv
$events | Group-Object Username | Sort-Object Count -Descending
```
</br>
<img align="center" width="800px" src="https://i.imgur.com/9QFuBKy.png" />
</br>

Determine when the failures occured:
```powershell
$events |
Sort-Object TimeCreated |
Select-Object TimeCreated, Username, Workstation, SourceIP, LogonType
```
</br>
<img align="center" width="600px" src="https://i.imgur.com/1gXw8mz.png" />
</br>

Determine how many failed attempts per user
```powershell
$events | Group-Object Username | Select-Object Name, Count
```
</br>
<img align="center" width="600px" src="https://i.imgur.com/zhVFac7.png" />
</br>

Identify the Status code:
```powershell
$events | Group-Object Status | Select-Object Name, Count
```
</br>
<img align="center" width="600px" src="https://i.imgur.com/ftWegJd.png" />
-1073741715 = Bad username or authentication information. The given credentials aren't correct. This issue might occur due to an incorrect user/password combination or username format
</br>

Identify the Substatus codes:
```powershell
$events | Group-Object SubStatus | Select-Object Name, Count
```
</br>
<img align="center" width="600px" src="https://i.imgur.com/4sITG9I.png" />
-1073741718 = User logon with misspelled or bad password

-1073741724 = The specified account does not exist
</br>

### Step 4: Analyze Account Lockout
Filter the Security log for Event ID 4740

Event ID 4740 = account lockout event:
</br>
<img align="center" width="600px" src="https://i.imgur.com/SiUKrK9.png" />
</br>

Display the XML field names to determine which user account was locked
```powershell
Get-WinEvent -Path ".\Evidence\Security.evtx" |
Where-Object {$_.Id -eq 4740} |
Select-Object -First 1 |
ForEach-Object {
    [xml]$xml = $_.ToXml()
    $xml.Event.EventData.Data
}
```
</br>
<img align="center" width="600px" src="https://i.imgur.com/0ktKNYT.png" />
</br>

Determine when the user's account was locked
```powershell
Get-WinEvent -Path ".\Evidence\Security.evtx" |
Where-Object {$_.Id -eq 4740} |
Select-Object TimeCreated
```
</br>
<img align="center" width="600px" src="https://i.imgur.com/xQVT4NM.png" />
</br>

## MITRE ATT&CK Mapping

| <h3>Technique</h3>	| <h3>Name</h3> | <h3>Justification</h3> |
| ----------------- | -------------------------- | ------------- |
|<p>T1110.003</p>	| <p>Password Spraying</p>   | Multiple failed network authentication attempts were observed against several user accounts originating from a single source workstation. The observed behavior aligns with MITRE ATT&CK's definition of password spraying. |

## Write Incident Report
Analysis of Event ID 4625 identified repeated failed network logon attempts against the Sarah, Jonathan, and df1admin accounts originating from source IP 98.122.240.33. The observed Logon Type 3 indicates that the authentication attempts occurred over the network rather than through local console access. The primary Status value, -1073741715 (Hex value=0xC000006D), combined with SubStatus -1073741718 (Hex value=0xC000006A), indicates repeated authentication attempts using valid usernames with incorrect passwords. Additionally, one event contained SubStatus -1073741724 (Hex value=0xC0000064), indicating an authentication attempt against a nonexistent account.

Event ID 4740 confirmed that the Sarah account was locked at 7/1/2026 3:14:50 AM. The Caller Computer Name field identified DESKTOP-OUPA0T1 as the system responsible for generating the lockout event. This same workstation was observed as the source of failed authentication attempts against the Sarah, Jonathan, and df1admin accounts.

Based on the correlation of these authentication artifacts, the observed activity is consistent with a password spraying attack, in which a single source system attempts authentication against multiple user accounts using one or more passwords. While additional evidence such as endpoint telemetry, network logs, or account lockout policy configuration would strengthen the assessment, the available Windows Security Event Log artifacts are consisten with these findings.

## Lessons Learned
Windows authentication artifacts provide valuable evidence for determining the cause of account lockouts and failed login activity. By correlating Event IDs 4625, 4624, and 4740, investigators can reconstruct authentication behavior, distinguish between benign user mistakes and malicious activity, and produce evidence-based conclusions.

More importantly, this lab demonstrates that effective DFIR investigations rely on correlating multiple artifacts within their proper context rather than drawing conclusions from a single event. This methodology forms the foundation of professional Windows forensic investigations and scales directly to enterprise incident response engagements.
