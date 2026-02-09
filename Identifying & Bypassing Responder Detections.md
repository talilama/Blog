# Identifying & Bypassing Responder Detections
It is nearly 2024, and broadcast protocols and lack of SMB signing are still default settings on Microsoft Windows hosts. This means the classic technique of broadcast traffic poisoning to relay Net-NTLMv2 via SMB is still a viable way to gain a foothold on an internal network. However, some Endpoint Detection and Response packages (EDRs) and Network Administrators have caught on and now use honeypot LLMNR and NBT-NS requests to identify and alert on broadcast poisoning attacks! The purpose of this blog post is to detail common tools used to set up honeypot broadcast requests and to detail how to identify these bait requests to continue poisoning broadcast traffic undetected.

Broadcast Poisoning Detection Tools
-----------------------------------

Several technologies can be used to detect broadcast protocol poisoning. The basic premise is to issue fake LLMNR and NBT-NS requests that should not receive any legitimate answers, as the requested resources do not exist. Any host that does answer the bait requests is assumed to be performing a malicious broadcast protocol poisoning attack and should be alerted on. 

This type of detection could be performed from a dedicated single server on each subnet, but then it is more readily identifiable by attackers. There are several open-source projects that can be used to implement this type of honeypot. Praetorian details a strategy to run a small PowerShell script from a variety of endpoints that requests and logs LLMNR and NBT-NS responses ([1](https://www.praetorian.com/blog/a-simple-and-effective-way-to-detect-broadcast-name-resolution-poisoning-bnrp/)). This is effective because to an attacker it looks like legitimate broadcast requests coming from multiple endpoints, and requests can be configured to match the naming convention of the company’s resources to further blend in. Using this method and disabling all legitimate broadcast protocol traffic is a highly-effective layered defense that prevents the attack, and also alerts defenders to the presence of any attackers attempting to poison traffic. 

Praetorian PowerShell Script
----------------------------

Running the default Praetorian PowerShell script from 192.168.0.149 results in the following output in Responder:

![Running the default Praetorian PowerShell script from 192.168.0.149 results in the following output in Responder image of code by white oak security](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/dfPXqiLqHrm_iBXaiB_R712sD5e_ccaKiIlBkzb2U_6hkCnRG7HjApMxnFYRPzki4aJyqOVV5imBVPpgkCfC1EfxpfCPNJeKxVpA56jLjw9U_wQWL9CORSpUxdU6a7igpN9qBLRcSlQDcCyIHxEj3_M.png)

Running Responder without Analyze mode poisons the request, and the Praetorian PowerShell script logs the activity in the specified log file as well as in the script console:

![Running Responder without Analyze mode poisons the request, and the Praetorian PowerShell script logs the activity in the specified log file as well as in the script console Image of code by white oak security ](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/Gl-UZ9iYSeeJ586MICqgsBI0lssc0OlrK-yZ_ILUOr8uBlocTeVzhvlNYpzj5Tt5FmzyT2IyD2kITAcBZ13Kxt0B4mYkA4qrvKoovPpEvjE5Bs1WipNeuHO9n-CVMI2l2L_Ierw_uUd5ESfLuSkF1bE.png)

This tool creates local log files (by default in C:\\tmp\\poisoning.csv) that are required to be forwarded to a Security Incident and Event Management (SIEM) tool or log investor for alerting. Additionally, it has options to configure a list of hostnames to be randomly chosen, as well as the time between requests and a “jitter�� to randomize the timing:

```
$logfile = 'C:\tmp\poisoning.csv'
$requestHosts = @('CORP-TX-FILE-01','COPY-NY-DC-02') #False hostnames to request
$interval = 30 #The minimum number of seconds to wait between requests
$jitter = 30 #The maximum value for a random number of seconds to add to the interval
```


### Conveigh

[Conveigh (2)](https://github.com/Kevin-Robertson/Conveigh) is another PowerShell tool that can be used to similar effect. The default settings will send randomly named LLMNR and NBNS requests at an interval between 2-30 minutes. I sped this up to send requests every 1-2 minutes for demonstration:

![Conveigh powershell tool screenshot by white oak security](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/fwCqLLfKB9ZpNSG9Z0-23YLmrR3OFkoDB2EotushAqLZIRi3QQ_Lp_1WInA9G7J5l_Z-zRTHhb5uOxDGlp7yomb5E6GdELL8FUDO3jjzzdpbW4GkFyGmsokp6BVgdl88OvlWeZeAIVQR2NNuXt_nqNk.png)

These show up in Responder looking like this:

![Conveigh powershell tool withing the responder screenshot by white oak security](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/MLmrMHYPaNmOxTjetaYrLH3GhscRmyTGLKfSYhaTC6ZvzDjVBPowFo9IXjAk7V7OXZk6iQY_G1O_22rupySbeLLQuo-KBzyT02ByfQB_LhXpygSs3I2xnhRCWD6GZbqTwMUybiVg4i4Ce7h0j-l-cLM.png)

Conveigh can also be configured to randomly choose a set of hostnames to blend in with the naming convention of an environment:

![Conveigh can also be configured to randomly choose a set of hostnames to blend in with the naming convention of an environmenT by white oak security](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/CVpnJPmH7D17WBvemibCmLYT6GO_kbsjSIUuiav07P3Jaa8hJ1YF-cH8vTFX2FN2CIVFvXk0qBE-tXsK7jI28DETGfBE7XyU-oiLYcIJa0pLBs9evvoRS_4B0phMRgZIGTw4HN_KxAxbe3M_5mkr4yQ.png)

This lends credibility and makes it more difficult to identify the requests as fake by attackers:

![Responder lends credibility and makes it more difficult to identify the requests as fake by attackers screenshot by white oak security](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/BalrqURxECE5AORTMSzlXi5AV7m75wcb16zvKed0Zd1tvZyJTmsjdkxggWWir5w7PuaCfm0ouKA3EplfFjKJdO9RlAZDhI-CGVZvwXoRhhjNdrLTYe3_ZpRdCmgMeV5BqYUlpLFqDmVwV1GHjzkEhmw.png)

File output can be enabled on Conveigh as well to log to a file using the **_\-fileOutput_** flag, which can then be ingested by an SIEM:

![File output can be enabled on Conveigh as well to log to a file using the -fileOutput flag, which can then be ingested by an SIEM Screenshot by white oak security ](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/wwk8Y1WjXTTTtNF4HeYN9Cwgg908-YoQgHF1wJa2xprXzmnPJ7JC-b2kIrvY8R0nPeUWJ1iOq0jtQqzxKvCi4UqZaCrZnHAPy8jdFNgWMFyQOL8ACK2wxUObLgJ1qJ4eF7yV-nYEBCqY9wIyNbCmc1o.png)

### Vindicate

[Vindicate (3)](https://github.com/Rushyo/VindicateTool) is another open-source broadcast poisoning detection tool written in C#:

![Vindicate (3) is another open-source broadcast poisoning detection tool written in C# screenshot by white oak security ](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/Vdd1c0Vfm3y-mlX5zV63UJpfBxU1Iy_JIKTuptLoJxc7Jx4206uXYsxPmxcAhJTNf0sZCDy_-NRStBfGGcm78BQ7npb9bIwAxPCIz8gQ81vv71T2k15JD_wn2ELfZgNWPuRQIfAjJ8QXOGAQCfkXEyc.png)

The default setting uses individual static names “ProxySvc” for LLMNR and “WPAD-PROXY” for NBT-NS requests:

![The default setting uses individual static names “ProxySvc” for LLMNR and “WPAD-PROXY” for NBT-NS requests Screenshot by white oak security](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/ip9_O48XWEFcD5FzLayapSSqgOItCRoqHYSzq3cM9UAu0ABB6IZAiz7h-noemS3Neen-p91GeHlNw7rYOo0J9bqBRIdTguPK1fDaH415lHiZFMUfdyz_2qf4WLoNxHwgJND8RXPxuFPx1UsiUOAVDws.png)

These can be configured to blend in with the environment’s host naming convention:

```
.\VindicateCLI.exe -v --mdns-lookup testsql.test.lab --llmnr-lookup filesrv1.test.lab -e
```


This tool is meant to be run as a service and will output results to event logs. The SIEM will need to be configured to alert on these custom events (see the Vindicate Github page for how to configure this).

### CanaryPi

[CanaryPi (4)](https://github.com/hackern0v1c3/CanaryPi) is another tool used for Broadcast Protocol honeypot-style detections. It is in Alpha stage and therefore was not tested for this blog post. It uses randomly generated names for the bait requests by default.

### EDR Vendors

#### Symantec Endpoint Protection

Symantec Endpoint Protection also includes options for this type of detection and performs fake LLMNR and NBT-NS requests from the endpoints themselves to make them look legitimate. This is a sample excerpt from Responder in Analyze Mode on a network with Symantec Endpoint Protection broadcast poisoning detections:

![Symantec Endpoint Protection also includes options for this type of detection and performs fake LLMNR and NBT-NS requests from the endpoints themselves to make them look legitimate. This is a sample excerpt from Responder in Analyze Mode on a network with Symantec Endpoint Protection broadcast poisoning detections - image code responder detection by white oak security](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/lbSk0ppi08r3-6OlrrwGg2IAx4CnaLHk--vdKivHYq1FBulFDYLHszaO_xQcqz0p3ewhsHrfMiKMTZJ3pthr1f-ooYyZEyCGqZV6-dJTnW_3NE6Xx9ttUyf5lYwE2GYdo4-SniVHmlCkHaQiyUT68S4.png)

The downside of this method is that the requested names are easily identifiable as random strings. I’m not sure if it is possible to modify the names to blend into the environment, as I did not have a test instance to experiment with. If this method could be configured to blend in, it is highly effective because the requests are initiated from actual workstations.

#### Fortiguard FortiEDR 

I was not able to test this, but Fortinet’s FortiEDR claims to have detections for these types of attacks ([5](https://www.fortiguard.com/encyclopedia/ips/49485)).

#### Rapid7 InsightIDR

I was not able to test this, but [Rapid7 InsightIDR (6)](https://docs.rapid7.com/insightidr/uba-detections) claims to have detections for these types of attacks. One note about InsightIDR is that apparently it is configured to detect Responder poisoning, but may not work to detect [Inveigh (7)](https://www.esecurityplanet.com/products/rapid7-insightidr-review/#network). This would be an interesting topic for further research.

Bypassing Responder Detections
------------------------------

The basic premise of bypassing these detections is to monitor broadcast traffic (e.g., using Analyze mode in Responder) to determine which broadcast requests are legitimate and which ones are bait, then only poison the legitimate ones. This requires two conditions:

1.  There must be legitimate broadcast traffic requests and not just bait ones.
2.  The bait requests must be distinguishable from the legitimate ones. 

### Identifying Fake Requests

The following is a list of hints to help with identifying bait broadcast traffic:

1.  Single source of requests – Network administrators may take the easy route and set up one of the above open-source tools on a single server per subnet rather than on multiple legitimate Workstations/Servers. 
2.  Random strings for names – Conveigh, CanaryPi, and Symantec Endpoint use randomly generated strings by default that stand out against a standard DNS naming convention.
3.  Default names – These honeypot tools may accidentally be run with default settings for request names. The Praetorian PowerShell script uses the following default names for broadcast requests: 

*   CORP-TX-FILE-01 
*   COPY-NY-DC-02

Vindicate uses the following default names for broadcast requests:

*   ProxySvc
*   WPAD-PROXY
*   apple-tv

4.  Timing – These tools may run with default settings at regular intervals. The default timing/jitter settings for the Praetorian script send requests every 30-60 seconds. The default settings for Conveigh send requests every 2-30 minutes. The default settings for Vindicate send one NBT-NS and one LLMNR request every 10 seconds. Analyzing the frequency of requests from each host may reveal a pattern that can then be applied to identify which requests are fake. Responder doesn’t show timestamps in the console output, but timestamps down to the second will be logged in the Responder-Session.log file. 

Note the below screenshot from Responder-Session.log has the same two requests sent every 10 seconds exactly (bait requests are from Vindicate):

![screenshot from Responder-Session.log has the same two requests sent every 10 seconds exactly (bait requests are from Vindicate) By white oak security ](https://blog.cyberadvisors.com/hubfs/Imported_Blog_Media/FgRUmOIPKCZeC97PIwemdu1JFYdDengEM0Av8pRUUOVwqqGZvKBuTY6kpks3ut0-45jQko1QDWtzVz0UIToXxi4yn-xYnOwzObpd8I79LrybJqynJJUbyaMwqvj3pY2VHzXqPmxF85ppdkzDD1RbxjI.png)

### Configuring Poisoning Tools to Respond to Legitimate Requests Only

Alright, let’s say you have identified some legitimate broadcast traffic and have a list of request names and IP addresses that you suspect are serving bait requests. Now you just need to respond to the legitimate requests and ignore the bait requests! The three common tools for poisoning broadcast requests all have options to filter on IP addresses or request names either via allowlist or denylist.

#### Responder:

To configure [Responder (8)](https://github.com/SpiderLabs/Responder) to ignore or respond to certain names or IP addresses, modify Responder.conf (the default location is /etc/responder/Responder.conf):

```
; Specific IP Addresses to respond to (default = All)
; Example: RespondTo = 10.20.1.100-150, 10.20.3.10
RespondTo = 192.168.0.149


; Specific NBT-NS/LLMNR names to respond to (default = All)
; Example: RespondTo = WPAD, DEV, PROD, SQLINT
;RespondToName = WPAD, DEV, PROD, SQLINT
RespondToName = 


; Specific IP Addresses not to respond to (default = None)
; Example: DontRespondTo = 10.20.1.100-150, 10.20.3.10
DontRespondTo = 


; Specific NBT-NS/LLMNR names not to respond to (default = None)
; Example: DontRespondTo = NAC, IPS, IDS
DontRespondToName = ISATAP
```


#### Inveigh:

[Inveigh (9)](https://github.com/Kevin-Robertson/Inveigh) has the following options to ignore or respond to only certain requests based on name or IP address:

```
.PARAMETER SpooferHostsIgnore
Comma separated list of requested hostnames to ignore when spoofing with LLMNR/mDNS/NBNS.


.PARAMETER SpooferHostsReply
Comma separated list of requested hostnames to respond to when spoofing with LLMNR/mDNS/NBNS.


.PARAMETER SpooferIPsIgnore
Comma separated list of source IP addresses to ignore when spoofing with LLMNR/mDNS/NBNS.


.PARAMETER SpooferIPsReply
Comma separated list of source IP addresses to respond to when spoofing with LLMNR/mDNS/NBNS.

```


#### Pretender:

[Pretender (10)](https://github.com/RedTeamPentesting/pretender) also has the “spoof” and “don’t-spoof-for” options to filter on names:

```
pretender -i eth0 --spoof "testsql.test.lab" --dont-spoof-for "CORP-TX-FILE-01,COPY-NY-DC-02"
```


Broadcast Poisoning Honeypot
----------------------------

Broadcast protocols like LLMNR, NBT-NS, and mDNS are still commonly found in internal networks and are still enabled by default even on recent Windows versions. There exist several robust and relatively simple-to-install tools that make it possible to detect broadcast poisoning. 

Defenders should make sure their broadcast poisoning honeypot meets the following criteria:

1.  Fake requests should be initiated from numerous legitimate Workstations and/or servers and not just a single dedicated server. 
2.  Fake requests should randomly iterate through numerous legitimate-looking hostnames (at least 5-10) that blend in with the naming convention of the rest of the network (make sure these fake hostnames are not in use). Neither default names nor random alphanumeric strings should be used as they are easily identifiable. 
3.  Honeypot broadcast traffic should have a random timing “jitter” to make fingerprinting bait requests by timing more difficult. Something like a 30-second interval with up to a five-minute random jitter would be difficult to identify. 

When these detection tools are configured and implemented correctly, they are nearly impossible to fingerprint as bait requests. However, if the above criteria are not satisfied, attackers may be able to identify and filter the bait requests. If legitimate broadcast traffic still exists, this allows them to fly under-the-radar and potentially obtain a foothold on the network via broadcast poisoning. This honeypot broadcast traffic technique in conjunction with effective Group Policy settings to disable legitimate broadcast traffic should be implemented on all internal networks for optimum security.


###### **Sources**:

1.  [https://www.praetorian.com/blog/a-simple-and-effective-way-to-detect-broadcast-name-resolution-poisoning-bnrp/](https://www.praetorian.com/blog/a-simple-and-effective-way-to-detect-broadcast-name-resolution-poisoning-bnrp/) – Praetorian PowerShell script and description
2.  [https://github.com/Kevin-Robertson/Conveigh](https://github.com/Kevin-Robertson/Conveigh) – Conveigh Github
3.  [https://github.com/Rushyo/](https://github.com/Rushyo/VindicateTool)
[VindicateTool](https://github.com/Rushyo/VindicateTool) – Vindicate Github
4.  [https://github.com/hackern0v1c3/CanaryPi](https://github.com/hackern0v1c3/CanaryPi) – CanaryPi Github
5.  [https://www.fortiguard.com/encyclopedia/ips/49485](https://www.fortiguard.com/encyclopedia/ips/49485) – Fortinet post describing their detection of Broadcast Protocol Poisoning
6.  [https://docs.rapid7.com/insightidr/uba-detections](https://docs.rapid7.com/insightidr/uba-detections) – Rapid7 InsightIDR Documentation describing “Protocol Poisoning Detected” 
7.  [https://www.esecurityplanet.com/products/rapid7-insightidr-review/#network](https://www.esecurityplanet.com/products/rapid7-insightidr-review/#network) – Blog post detailing Rapid7 InsightIDR not detecting Inveigh 
8.  [https://github.com/SpiderLabs/](https://github.com/SpiderLabs/Responder)
[Responder](https://github.com/SpiderLabs/Responder) – Responder Github
9.  [https://github.com/Kevin-Robertson/Inveigh](https://github.com/Kevin-Robertson/Inveigh)  – Inveigh Github
10.  [https://github.com/RedTeamPentesting/pretender](https://github.com/RedTeamPentesting/pretender) – Pretender Github
