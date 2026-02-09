# Bypassing Microsoft Defender For Identity Detections
![Bypassing Microsoft Defender For Identity Detections By white oak security ](https://blog.cyberadvisors.com/hs-fs/hubfs/Imported_Blog_Media/QaTKw7brLf9KRYlwAbGUilnaO_jEAzmEl1n7Ar1GUAh1e8vlywmxOivwZPuUC_IYh9XAnzd9rPnCebPtidQBezxqpBNvFyXc5hCKWL5FBNlW-6i99O4_PUFNi_CUXrXhvio30jTV0LZCfjurVNYe7T2FdIu6577t.png?width=716&height=298&name=QaTKw7brLf9KRYlwAbGUilnaO_jEAzmEl1n7Ar1GUAh1e8vlywmxOivwZPuUC_IYh9XAnzd9rPnCebPtidQBezxqpBNvFyXc5hCKWL5FBNlW-6i99O4_PUFNi_CUXrXhvio30jTV0LZCfjurVNYe7T2FdIu6577t.png)

On a few recent internal penetration tests, I found common tools and techniques for Active Directory attacks being detected by [Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/what-is) (formerly known as Azure Advanced Threat Protection/Azure ATP. Defender for ID is incredibly powerful in its default configuration and relatively easy to set up. Additionally, it includes functionality for custom queries and threat hunting, making it an excellent tool for defenders. I will not go into install steps in this post, as they are [well-documented already](https://learn.microsoft.com/en-us/defender-for-identity/prerequisites). 

I decided to install the default configuration of Defender for Identity in my small Active Directory test lab to test certain methodologies and gain insight into the detections provided by Defender for ID. This blog post will detail how detections are implemented in Defender for ID for several common attack paths, along with some bypass options that are working as of Nov. 3rd, 2023.

Kerberoasting
-------------

I ran a default run of Kerberoasting using [Impacket](https://github.com/fortra/impacket).

```
python3 GetUserSPNs.py -request -dc-ip 192.168.0.150 test.lab/t -outputfile kerberoast.txt
```


### Detection

This led to the following alert in the [Microsoft 365 Defender Portal](http://security.microsoft.com/), which is the control panel for Defender for ID among other tools:

![Kerberos SPN exposure screenshot by white oak security](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/dBOy-oPYMv0DpQGa9Yczc5UqZNlO6RSlCAi0JokcLmdy9P2x6j3-f9jN4nrP3Fo3U6tVb5D6CKNxzVna83QAf9VEjUbRS1gx3-p077NilROPh22HemXP48G98dHnIvyzBk8OgZ5ARIgHvNoSID7yublvEunrT7Se.png)

Selecting the timestamp at the bottom, we see the “Search Filter” is an LDAP query used to identify Kerberoastable accounts:

![LDAP query used to identify Kerberostable by white oak security](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/7WY8AKu9rSHiSxWYAIpI8b1X1I0ksj1LfaKqUbiLCXqROlDk-kdQCnBsjG9pKyZhYaHp_vIvT0vc3t-fCANo8MvRxglKnv467fIxJ4fkk8nvwMwG1D-Oe6ZQU6mH4EkDPPg_TeJ2fqm3hSLwmXNH2cq5_M1imjG6.png)

### Bypass

This information tells us that Defender for Identity uses the LDAP query for initial detection, and then appears to pull SPN ticket requests that immediately follow the LDAP query. This likely is done to cut down on false positives but means that we can easily bypass this detection.

Examining the code within Impacket’s GetUserSPNs.py we see the following LDAP query used for a search filter:

![Examining the code within Impacket’s GetUserSPNs.py we see the following LDAP query used for a search filter screenshot by white oak security ](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/H1XH3GyizxsqCY5Rk79drZRSqznDJHYfXLRX8ltUCVcHjU2jlRFt3HTI1MbWwJ5kF-k9WmjTfwd7FVy9EEYD3TVdjR4RdJ4izVoasmNHJAHm6f8YHU9G6GwiwjweupW11TKtv4zG9zvqR8QNyhACJ5QmjxqGyQIG.png)

I attempted to bypass detections by rearranging the parameters within the query, but the modified query was still detected. It might be possible to break up the filter with individual queries to get a list of all Kerberoastable users, but this information can also be obtained via other tools such as Bloodhound or “Active Directory Users and Computers”. Once that list is obtained, individually requesting Kerberos SPNs does not result in any alerts.

The screenshot shows executing an undetected Kerberoast attack via Impacket with a single user:

![The screenshot shows executing an undetected Kerberoast attack via Impacket with a single user by white oak security ](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/oY7ISaFbXVeba0CXDGLCRONLnZ4b9v3UtYnD3UVrWEtRQrjG7kBCEX_GfSiCiG5Znp1DREVxAExtqvtKPoVXfhGl0dd5OFfJsvbPVZ5BEzsN6KVGpcyFGG5a5XCVSK_uNySsZ7LGsnuu6qzMgDQh7LeSQ5Gn86W2.png)

```
python3 GetUserSPNs.py -request -dc-ip 192.168.0.150 test.lab/t:Password123 -outputfile kerberoast.txt -usersfile ~/krbusers -debug
```


![Screenshot of code by white white oak security shows the Microsoft defender bypass](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/04PlSmxyoqIQ5dKeBwfVKw-t3dxubFZ97QDLY6hEqNyuoCB9A8ztcP2BxEUUPXsbEycSBVA8in_3fm33UAvAFq5sXRCXhXwu_diu1LDQ9jk052S_6q9UAY9GvBUdzQkVwFG5lm8ih2HrOZITQa7OgxQ4ZKhKDPaD.png)

AS-REP Roasting
---------------

Running an [AS-REP roasting attack](https://harmj0y.medium.com/roasting-as-reps-e6179a65216b) using a list of common usernames resulted in a Medium-Risk alert in the portal.

### Detection

[Kerbrute](https://github.com/ropnop/kerbrute) was used to perform the AS-REP Roasting:

```
kerbrute userenum –dc 192.168.0.150 –delay 100 -d test.lab -o kerbrute.log -v ~/opt/testusernames.txt
```


This generated the following alert in the Defender Portal:

![New alert in the defender portal screenshot by white oak security during AS-REP Roasting through kerbrute and impacket ](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/vDVhFIW_PES-tXYNkooNaHxB1kIhTf6KvP7SATmQHQ4OAj4I2uydB6wIlXMzpBjA1OybZRVn6pAFma66PWLx4psz_R7xgdeChh437GFVqvSY1XpCVkAdpAWZ4SduP3Eu5RmIFKUbd0SSdpCMBQ_N2FJm_aElmGcl.png)

### Bypass

There appeared to be no way to bypass this detection, and the account performing the reconnaissance was automatically disabled by Defender for ID, resulting in the inability to perform further enumeration:

![Kerbrute screenshot by white oak Security for bypassing Microsoft Defender for identifying ](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/r4a-GwyCyclSrxCmHp7PgKbg0nIEoDiurqUnAE4PcvxYfW-dt-NZa_OxZfp5FiK4NvoUJYS_nnqIrp77lPnT7TG29zMKWI4S_mEUehvY4REWue0_IxuK8GGJ9NmAUqbhuKV6k4ozL4lmEoyOAN3e1_1mgYTfaYOZ.png)

One interesting note is that the number of guess attempts and successfully guessed users in the console appeared to be incorrect. My run included 919 usernames and 8 valid accounts:

![One interesting note is that the number of guess attempts and successfully guessed users in the console appeared to be incorrect. My run included 919 usernames and 8 valid accounts.](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/gmDnTNSfDTtDHil6Mpp3ozZ6fmgjHNU2tF0YUC0YHkq2r1AxH0XXTpizMJox-WbseWVaZlZDCpUx8kpT7ZdBZ14YvNzZgmiTtZbA5P5QZZZaROeDI-topbJS3A8pMWP8monXlM5B5vAp8b83FBlZyMlYkt0t8w0e.png)

However, the Defender Portal showed only 156 guess attempts and 6 valid accounts:

![However, the Defender Portal showed only 156 guess attempts and 6 valid accounts Screenshots by white oak security ](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/852TrF-RZX0FDoWea0NQ3kc1y3_PMCT4gQLKI1N25C6oExSL7rUKx5UlENVuX2DzH8m2_iggkJubFJi-_FfBIjh3Evp0ovlGOup_cfO1Zu-InwRpvqtov58NmEP1rIWvn15UOfEesWxLnOb4tcw0xgrb0eLNoWO6.png)

Code Execution
--------------

Several common methods of code execution were performed against a host using credentials as well as NTLM via pass-the-hash for authentication. 

### Powershell Remoting

Executing commands via Powershell remoting was performed using [evilwinrm](https://github.com/Hackplayers/evil-winrm). Code execution using credentials and pass-the-hash both resulted in a medium-risk alert:

![Executing commands via Powershell remoting was performed using evilwinrm. Code execution using credentials and pass-the-hash both resulted in a medium-risk alert Screenshot by white oak security ](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/E0oCgy_zOtnZxfdZ1Bt_1zig2yHA-XNezrnmM8COUu0024P1pbM1x8x-rzUYtR4NUJ0NLCG0kCqPUFxml2wv1wcm94mvz8Jmqf0vSVVNPxufz3MeSxRN5w_isiW_FCie8Zs7SKIzGYI1PrWQHe8ba5jo7pj5unNa.png)

![Executing commands via Powershell remoting was performed using evilwinrm. Code execution using credentials and pass-the-hash both resulted in a medium-risk aler in the defender portal by white oak security ](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/J2cN2_R7eq3dGH_kBfmmt_ei8aPmnkNm4J9bzPFIsVwMT1Yn8NPBrlKwg0-Wkf1VPKUZHHVwQpOIHFBdy3vC8a-J7VhkC278-wTzScOv4uMp0whetjsVTBd7dZXHad3YnEaEvS0cGd07XhPI6BESP4Y72mXGORgg.png)

However, it appears that the actual commands that were run did not get logged. An interactive session via EvilWinRM resulted in the following logged output in the Defender Portal:

![However, it appears that the actual commands that were run did not get logged. An interactive session via EvilWinRM resulted in the following logged output in the Defender Portal By white oak security ](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/bVoxA_qIFMY1mkPmMLLVLtQ8gBb-tfFbiznW0UK0oB4VaMF8-dqaYSSR3RrKTWhEFLOQNXoaAW2fzoCCrUg7W5OupIxx2lvZ1yl-5leOo3RGJxNVzTgb_3m6oY3xS4CqM2X_TnE8m0_GmJDPhU-eR8MZot6Qm-jP.png)

### RDP

Connecting to a device via RDP with credentials did not trigger any alerts in my test lab, although this may be dependent on the Defender for ID learning period determining which RDP logins are suspicious or not:

```
xfreerdp /v:192.168.0.150 /u:t /p:’Password123!’
```


![Connecting to a device via RDP with credentials did not trigger any alerts in my test lab, although this may be dependent on the Defender for ID learning period determining which RDP logins are suspicious or not Screenshots by white oak security ](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/mKz60IKx9lPSU7rF4txZ5ZNcZx1EIvl97g6U-rgFeVOsZ-tfInxQZsHu13hjbJWc69P_UD4qq6DoxPwcv06pjMLEJ4jYtG-KEA-BAwow1qCydAdo6LHROxcFWoXypUr9oSTpA21dqqHSnAFnUoY5vtfD6VsdBOb-.png)

### PSexec & WMIexec

Using either Impacket’s psexec.py or wmiexec.py with credentials or pass-the-hash results in a high-severity alert in the Defender Portal:

![Using either Impacket’s psexec.py or wmiexec.py with credentials or pass-the-hash results in a high-severity alert in the Defender PortaL screenshot by white oak security ](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/nd9zQfgOGPFubnaZNBma2LRC8A-jsI5ZPgIEnu55yTOA-LAi1tsTUrdRqibx0ku355il2-V4yfxut75spUmLZB8Lf7MkeEtkgn3JTRQMEow9SEum3q0vdHdhCfauRWl33n9N20cu3htGCh91ZaZzPQIzhk9P8q5z.png)

Further research to determine what artifacts trigger the Impacket detection would be interesting but was beyond the scope of this blog. 

### DCOMexec/MMCexec

Using Impacket’s dcomexec.py did not generate any alerts using password or pass-the-hash:

```
python3 dcomexec.py -debug -silentcommand t:’Password123!’@192.168.0.150 ntdsutil.exe ‘ac I ntds’ ‘ifm’ ‘create full C:\Windows\Temp\169108586’ q q
```


![Using Impacket’s dcomexec.py did not generate any alerts using password or pass-the-hash Screenshot by white oak security ](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/bnMyfQ8VBF0i5t7Xyp8tCBBu5iCPnw0XIBQ2uYZw5ZfbVHHII9-mtLi0Ua4mrh2C_duz0LXP__FWvQAMcJ2w0thF4KAvP2ND32YQQf7cuc_MT8ZqDLGp411VI86--wGKHT_qJjLXPOjHUBHgiUTp0jziYNMo1a9R.png)

However, any commands that require elevated execution will result in a UAC prompt and will require a UAC bypass to gain code execution as SYSTEM.

The reasoning for DCOM/MMC not generating alerts is hinted at in a [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec/blob/master/cme/protocols/smb/mmcexec.py) [comment](https://github.com/byt3bl33d3r/CrackMapExec/blob/master/cme/protocols/smb/mmcexec.py), noting that it does not generate noisy event log messages:![](https://blog.cyberadvisors.com/hs-fs/hubfs/Imported_Blog_Media/g4GJthHt_ZMTFNPoH0s14DNqxl8CJsKZDTO60sPBUL6uFNb-TnWt-OqeT4Imnmfoi-ev3a1AhW-WeWFNqli0HkwA9Wo21q9R4VGm8ywXjM77NG0jY4-eq2XQD9wJpDLOd3_-B7O1WYAVGNtQL9iK2z_UpGMKbeCV.png?width=624&height=510&name=g4GJthHt_ZMTFNPoH0s14DNqxl8CJsKZDTO60sPBUL6uFNb-TnWt-OqeT4Imnmfoi-ev3a1AhW-WeWFNqli0HkwA9Wo21q9R4VGm8ywXjM77NG0jY4-eq2XQD9wJpDLOd3_-B7O1WYAVGNtQL9iK2z_UpGMKbeCV.png)

### Crackmapexec/NetExec

Using CrackMapExec for command execution essentially uses smbexec under the hood by default, but results in a Medium-severity alert instead of a high-severity alert in the Defender Portal:

![Using CrackMapExec for command execution essentially uses smbexec under the hood by default, but results in a Medium-severity alert instead of a high-severity alert in the Defender Portal Screen shot by white oak security](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/0SVX_h9EMuZJtfqobsBRJJeduEQlQY8WksFpYoPJJAeFZa04UEvyLc9fCqdQUjQD4o4Ffn4mhDjHkAL9tMtf01askhroi-o5Q-9fYkgHpbJbNRvFMkOM5SU-_1dzvraihXauO3P1N5AbTf-et-olMulNo_SQd_wU.png)

Dumping NTDS
------------

There are three common methods for dumping NTDS.dit from a domain controller: DRSUAPI (DCSync), Volume Shadow Copies (VSS), and ntdsutil.exe. 

### DRSUAPI

The following CrackMapExec method for dumping NTDS uses DRSUAPI by default:

```
crackmapexec smb 192.168.0.150 -u t -p Password123 --ntds
```


![The following CrackMapExec method for dumping NTDS uses DRSUAPI by default Screenshot by white oak security ](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/06peEnf7MbEtjVGpRqBz55m2HgPVM_AYy1CPPsWnOSoTJAP1KrIm1BlRJIygLymOIO1_XGiTL6InvVdE-mmn5gnMOyznZwCuImsFmMmTU7RuJVKfQr46iy8dqhZlEVXbTLWH9SalECmmSSA-uXQJvTDVhYNF0pjk.png)

The default Impacket secretsdump.py method for dumping NTDS also uses DRSUAPI by default:

```
python3 secretsdump.py -just-dc-ntlm test/t@192.168.0.150
```


![The default Impacket secretsdump.py method for dumping NTDS also uses DRSUAPI by default Screenshot by white oak security ](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/esgYD42wE0w7xYrD88MRJWF5Kf8eT1yYmTQRJLHZ3i2Ua1Aml5XtUddGETLmKxDZ1dKrPPVLVfzdX5oPk4pb8NKMdUKiOM3xYK3Gaphij6eBccQRJVttWKT6QAIulxfesKvKAK3FPtu66BFqFaSyYnLlPon1IVsF.png)

Both of these result in a high-severity alert in the Defender Portal:

![Both of these result in a high-severity alert in the Defender Portal Screenshot by white oak security ](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/RAFOjqfS4B-IFgDyL19G7AURB0KRrEvCugppbi0eesaUTvqovMQWxAglvJPWJgwRnt6-8re7Fdz9c7eWPbdEcaSaunz8oJAor3o8XvKCKHRgoT_VNgHV3QfR53KC6nsgqLvWx5Qs7PJDx7NE4vv9Uv6JyIb6yzlr.png)

### Volume Shadow Copy

Crackmapexec and secretsdump both have options to use Volume Shadow Copy (VSS) instead of DRSUAPI. 

Crackmapexec uses the following syntax for dumping NTDS via VSS:

```
crackmapexec smb 192.168.0.150 -u t -p Password123 –ntds vss
```


![Crackmapexec uses the following syntax for dumping NTDS via VSS screenshot of code by white oak security ](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/zb8pYrkJKGHO_995EI_q48miohIaDzTgWZuSSyWnokRVG5nqVbJtJQDhccStUyVYVxVhybmP72XswOfaIeyL4_o3nj4xbd1q6TlZNmja8ch-YvFfH4zAJQny9_72ubgQeTbJFzqB9GYQu28fNHDrdPVB-p_JAG0Q.png)

This results in successful execution, but still generates the medium-severity alerts associated with CrackMapExec code execution:

![This results in successful execution, but still generates the medium-severity alerts associated with CrackMapExec code execution Screenshot by white oak security ](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/jHyu8VAKkjGvlJoPeX5QJmfkMzudeWqH8gwNB3_Qc84mJud-mUrjSIySk_Qdzhm4IHMsv2TYVakJ2Rgiyn3EB0MeUsTo-joIcdffi14sSbkwBJrPVrRGPxp2nt1nP00RBFr2-5DWFXia790j0Oui63FSyuxLWIh6.png)

Impacket uses the following syntax for dumping NTDS via VSS:

```
python3 secretsdump.py -just-dc-ntlm test/t@192.168.0.150 -use-vss
```


![Impacket uses the following syntax for dumping NTDS via VSS Screenshot by white oak security ](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/t8s1DdQ3u4HYxZVTK_3kZLfdXfvUJZ7YCcp4BMsQgZxVUTkTaKVs2NMzBCTRvLHYlxeRisAbxeXVfH8MkfTE1vE-kgw6elBQ7m49MgOL7s3baIqlAf8-spxMqVFW3-cFi9lV598SquHDysms8KGX4uFh8lWq_Hh5.png)

This method still results in the above “Suspicious service creation on one endpoint” alert due to secretsdump.py using SMBexec under the hood.

Attempting secretsdump using WMIexec results in the command failing to create a Volume Shadow Copy to dump NTDS and generating a new alert:

```
python3 secretsdump.py -just-dc-ntlm test/t@192.168.0.150 -use-vss -exec-method wmiexec
```


![Attempting secretsdump using WMIexec results in the command failing to create a Volume Shadow Copy to dump NTDS and generating a new alert Screenshot by white oak security ](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/-8R1oZzOQGB_7yr5dpa8MHXmw_W8oRk7uCIk5k-rvyXZZSPzz8CTnhVV0TGo81Gh6wextBUfPyowVsFFH5xwlURvV9kRA1GWmg7ezMVb2hjw9lfiM5Xu25H9A3hM08qR-EiAIuRj2do-nQ3lrtHxn2PRNDzNBY5i.png)

![Attempting secretsdump using WMIexec results in the command failing to create a Volume Shadow Copy to dump NTDS and generating a new alert In the defender portal by white oak security](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/Cj9YOXAfgCgrJLOi96IEZb_Vl729tpCtrEvn4RotOeU1P9iJVE-O7-4IdE-mUIENq8ZwsdiIfuIvn2W704_Mjbl8yvFVN7h0IdeyuNS5Aabf_7pzJU7JKCHsADvaMoDNwoMjeXsq2HiBjT_p6grUCMdGDAQdoRea.png)

Using secretsdump with the MMCexec option successfully dumps NTDS without generating any alerts:

```
python3 secretsdump.py -just-dc-ntlm test/t@192.168.0.150 -use-vss -exec-method mmcexec
```


![Using secretsdump with the MMCexec option successfully dumps NTDS without generating any alerts Screenshot by White Oak Security ](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/v_js3pDpvwIFyQCX4Du8U1hGdfrTNXgnb8lTw_YhbLwjYQejgWBMIGALgAssQRkTKuRPVg9qkIMx5QZzM71OrJnvB1ADB24XpJlXONKFe1N16-laIoPrcuh6dbhCki97gT1xQVWuLPBk-GUUxC1eTgm39aosxcYh.png)

This is interesting as well because it implies that secretsdump includes a UAC bypass that can be used in conjunction with MMC/DCOM execution that is not included in the dcomexec.py script. 

### Ntdsutil.exe

Using ntdsutil.exe surprisingly did not generate any alerts:

```
ntdsutil.exe ‘ac i ntds’ ‘ifm’ ‘create full C:\Windows\Temp\testasdf’ q q
```


![Using ntdsutil.exe surprisingly did not generate any alerts Screenshot by white oak security ](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/9bdGqDQnxhVJ4z8LkIsu-hzHZXLU_FbjyuzYnDVW7dHfNd6JxMavP-P9UJs3_8H5YupnC449vBusfFQ3Uwe6B1uZMQc0I9a-pgPgg4eKpndAmVoOxEnqk-eLvJKMvWH4aInA95t0uQXDpUkeYkKM6d8Z6FMISkMa.png)

This method requires elevated remote command execution as well as a way to retrieve the local files from the domain controller.  

Microsoft Defender For ID Conclusion
------------------------------------

Microsoft Defender for ID is very robust right out of the box and makes life difficult for attackers attempting to fly under the radar. It provides excellent insight into attacks and automatically disables accounts suspected of being compromised or used in an attack. However, as this post demonstrates there are several methods for bypassing these detections that can be used by red teamers or penetration testers to achieve their objectives. From my testing, RDP appeared to be the most reliable way of achieving code execution without setting off alerts, with unmodified pass-the-hash capable tools being difficult to use without detection.

### MORE FROM OUR TECHNICAL BLOG

Cyber Advisors specializes in providing fully customizable cyber security solutions & services. Our knowledgeable, highly skilled, talented security experts are here to help design, deliver, implement, manage, monitor, put your defenses to the test, & strengthen your systems - so you don’t have to.

[Read more from our technical experts...](https://blog.cyberadvisors.com/technical-blog)

### Learn More
