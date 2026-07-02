# Authentication Artifact Analysis
<img align="center" width="800px" src="https://i.imgur.com/GtZorHR.png" />

## Overview

Authentication failures are among the most common indicators encountered during security monitoring. While repeated failed logins may simply result from a user forgetting a password, they may also indicate password spraying, brute-force attacks, stale credentials, or misconfigured services.

For this lab, Windows 11 virtual machines were deployed to simulate authentication activity. Login failures were intentionally generated to create a realistic dataset for investigation, allowing you to analyze patterns and determine whether the behavior reflects normal user activity or a potential attack.

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
- Document investigative findings using professional DFIR methodology

## Windows Artifacts Examined

This investigation focuses on several key Windows Security events.

| <h3>Event ID</h3>	| <h3>Description</h3>       |
| ----------------- | -------------------------- |
|<p>4625</p>	      | <p>Failed logon attempt</p>|
|<p>4624</p>        | <p>Successful logon</p>    |
|<p>4740</p>        | <p>Account locked out</p>  |

Primary evidence source:
Security.evtx

## Investigation Workflow
The investigation follows a methodology commonly used during enterprise DFIR engagements.
### Step 1: Review Provided Evidence

You have been provided with a preserved Windows Security Event Log (Security.evtx).

Ensure you are working from this evidence file rather than a live system. Maintaining the integrity of original evidence is a fundamental forensic principle and allows investigators to revisit findings without altering the source data.

### Step 2: Identify Failed Authentication Attempts

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
-1073741715 = Bad username or authentication information - The given credentials aren't correct. This issue might occur due to an incorrect user/password combination or username format. [Reference](https://learn.microsoft.com/en-us/troubleshoot/power-platform/power-automate/desktop-flows/invalid-credentials-errors-running-desktop-flows#:~:text=without%20this%20requirement.-,%2D1073741715,-Bad%20username%20or)
</br>
<img align="center" width="600px" src="https://i.imgur.com/ftWegJd.png" />
</br>

Identify the Substatus codes:
```powershell
$events | Group-Object SubStatus | Select-Object Name, Count
```
-1073741718 = User logon with misspelled or bad password [Reference](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625#:~:text=Information%5CSub%20Status-,0xC000006A,-%E2%80%93%20%22User%20logon%20with)
-1073741724 = The specified account does not exist[Reference](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55#:~:text=account%20already%20exists.-,0xC0000064,-STATUS_NO_SUCH_USER)
</br>
<img align="center" width="600px" src="https://i.imgur.com/4sITG9I.png" />
</br>

