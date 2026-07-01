# Authentication-Artifact-Analysis
!([Event Viewer](https://i.imgur.com/a/Iz2C7bi))

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



