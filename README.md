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

### Step 2: Identify Successful Authentication

Filter the Security log for Event ID 4624
</br>
<img align="center" width="600px" src="https://i.imgur.com/gqi6o3O.png" />
</br>
</br>

Examine the successful logon event and note the authentication information
</br>
<img align="center" width="600px" src="https://i.imgur.com/q1rx7nA.png" />
</br>

### Export the successful logon events toa  CSV:
Get-WinEvent -Path .\Evidence\Security.evtx |
Where-Object {$_.Id -eq 4624} |
Select-Object `
    TimeCreated,
    @{Name='Username';Expression={$_.Properties[5].Value}},
    @{Name='Workstation';Expression={$_.Properties[13].Value}},
    @{Name='SourceIP';Expression={$_.Properties[19].Value}},
    @{Name='LogonType';Expression={$_.Properties[10].Value}},
    @{Name='Status';Expression={$_.Properties[7].Value}},
    @{Name='SubStatus';Expression={$_.Properties[9].Value}} |
Export-Csv .\Evidence\SuccessfulLogins.csv -NoTypeInformation



