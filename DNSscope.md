# DNSscope: Tool for Automating DNS Recon
Oct 11, 2024 1:00:40 PM 

White Oak Security Introduces DNSscope Tool White Oak Security’s experts created a tool to make performing deep attack surface analysis and identifying assets quicker – introducing DNSscope, a tool for \[…\]

White Oak Security Introduces DNSscope Tool
-------------------------------------------

White Oak Security’s experts created a tool to make performing deep attack surface analysis and identifying assets quicker – introducing [DNSscope](https://github.com/WhiteOakSecurity/dnsscope), a tool for automating DNS reconnaissance and attack surface identification. 

The purpose of this tool is to make it faster and easier to go through the steps of performing deep attack surface analysis to identify assets that belong to a target. When mapping the external attack surface of a target, there are several excellent tools such as [Amass](https://github.com/OWASP/Amass) (1) and [Sublist3r](https://github.com/aboul3la/Sublist3r) (2) that include the ability to identify subdomains via reverse DNS, open-source intelligence, and subdomain brute-forcing (among other capabilities). However, the results from these tools often include additional top-level domains and other information that requires further analysis. The process for evaluating these results is a prime target for automation.  

DNS Recon
---------

DNS Attack Surface Reconnaissance Process
-----------------------------------------

The basic process for DNS attack surface reconnaissance usually consists of the following steps (not necessarily in this order):

1.  Determine the top-level domains (TLDs) associated with your target.
2.  Determine the IP address ranges owned by your target.
3.  Run reverse DNS (rDNS) queries on the discovered IP addresses.
4.  Run forward DNS (fDNS) queries on the identified domains from reverse DNS to determine if they resolve back to the same IP address. If they resolve to other IP addresses, run additional enumeration to determine if those IP addresses also belong to the target.
5.  If additional IP addresses associated with the target are part of larger CIDR blocks, replicate the above steps to identify additional resources.
6.  Run subdomain enumeration on the identified top-level domains for the target.
7.  Identify any additional TLDs within the reverse DNS enumeration and repeat the process of subdomain enumeration.
8.  Run forward DNS queries on the enumerated subdomains to see if they resolve to the in-scope IP address ranges. If they resolve to other IP addresses, run additional enumeration.
9.  Enumerate TLS certificates associated with all identified resources, using the Common Name (CN) and Subject Alternate Name (SAN) fields to identify additional domains and subdomains associated with the target. Once identified, the same above steps are replicated for each of these resources.  

While Amass and Sublist3r are excellent at automating subdomain enumeration, the above process is often done manually. This makes it slow and difficult to complete thoroughly, especially for large companies with a complex attack surface. 

DNS Scope
---------

DNSscope aims to automate this process, making it faster to identify domains and subdomains associated with a target, and organizing them based on IP ranges and top-level domains. This process can be simplified to a set of steps to be performed recursively for each IP address and identified domain (TLD or subdomain):

#### IP Addresses:

1.  Run rDNS query.
2.  Run fDNS on all domains returned from rDNS query.
3.  If IP address is part of in-scope IP range, run TLS enumeration.
4.  Run the below Domain enumeration steps for all identified domains from steps 1 and 3.

#### Domains:

1.  Run DNS query to determine IP addresses associated with the domain. 
2.  If the domain contains a new top-level domain that hasn’t been seen yet, determine if this domain is actually associated with the target or if it is part of a hosting provider or some other entity. This process must be done manually. If the domain is associated with the target, run subdomain enumeration and run the domain enumeration steps for each identified domain.
3.  If TLD of the domain is determined to be in scope, then run TLS enumeration to identify additional resources. Run the domain enumeration steps for each identified domain. 
4.  Each domain is then sorted into the following categories:

*   Explicitly in scope: Domain resolves to IP in the provided IP range associated with the target.
*   Likely in scope: Domain isn’t explicitly in scope, but the TLD for the domain was determined to be associated with the target.
*   Out of scope: This category is only used for the non-default –tlsall setting, and includes identified resources that were not in the above two categories.
*   Dead domain: Domain does not resolve.

DNSscope
--------

DNSscope requires a file with IP address ranges to be passed to it. It begins by importing those IP addresses and using them to determine what resources resolve to IP addresses within the file and are categorized as explicitly in scope. The tool can also optionally be passed a single top-level domain ( -d tld.com ) or a file with a list of top-level domains ( -D domainsfile.txt ). Each of the IP addresses and domains is then placed into their respective queues, and the above enumeration steps are performed. 

For example, let’s pick a random company to run DNS enumeration on: Toyota. For Toyota, we do some initial research and find their main public external network to be 162.246.76.0/22, so we add those IPs to a file (DNSscope doesn’t support CIDR notation yet, so the tool “prips” can be used to expand the addresses):

```
prips 162.246.76.0/22 > toyota_prips
```


Then specify the file and a single domain with the ‘d’ flag to start. DNSscope will ingest the IP addresses and begin subdomain enumeration on the provided domain:

```
python3 dnsscope.py -i toyota_prips -d toyota.com
 
2022-03-14 14:39:00,627 INFO     Starting DNSscope
2022-03-14 14:39:00,627 INFO     Processing IPs from toyota_prips
2022-03-14 14:39:00,631 INFO     Searching for subdomains of toyota.com. This may take a few seconds...
2022-03-14 14:39:12,669 INFO     (+) SUBDOMAIN ENUM DISCOVERY: ADDING TO QUEUE: ccauto.toyota.com
2022-03-14 14:39:12,669 INFO     (+) SUBDOMAIN ENUM DISCOVERY: ADDING TO QUEUE: perspective.test.toyota.com
2022-03-14 14:39:12,669 INFO     (+) SUBDOMAIN ENUM DISCOVERY: ADDING TO QUEUE: losapp-cert.tfs.toyota.com
2022-03-14 14:39:12,669 INFO     (+) SUBDOMAIN ENUM DISCOVERY: ADDING TO QUEUE: developer-qa.apic.toyota.com
2022-03-14 14:39:12,669 INFO     (+) SUBDOMAIN ENUM DISCOVERY: ADDING TO QUEUE: dealerdailyddc-int-test-dev.toyota.com
2022-03-14 14:39:12,669 INFO     (+) SUBDOMAIN ENUM DISCOVERY: ADDING TO QUEUE: oaddrmdreports.toyota.com
2022-03-14 14:39:12,669 INFO     (+) SUBDOMAIN ENUM DISCOVERY: ADDING TO QUEUE: user63-86-140-78.toyota.com
2022-03-14 14:39:12,669 INFO     (+) SUBDOMAIN ENUM DISCOVERY: ADDING TO QUEUE: ddcpsqa.1dd.toyota.com
. . . 
```


When additional domains or IP addresses are discovered, they are also placed in the queue. When a new TLD is discovered, the default behavior of DNSscope is to prompt the user on whether they want to add it to the scope. If they choose yes, then the TLD is added to the “tentatively in scope” list, subdomain enumeration is performed on the new TLD, and all identified resources are added to the queue. The interactive prompt for new TLDs was chosen because it is often necessary to research whether the discovered TLD is owned by the target.

With the Toyota example, the buyatoyota.com TLD appears to belong to the organization, so we add it to the scope. 

```
. . .
Processing domain: origin.staging-ws.oat.aws.toyota.com
Forward DNS lookup for origin.staging-ws.oat.aws.toyota.com
(-) fDNS lookup failed on: origin.staging-ws.oat.aws.toyota.com
Finished processing domain: origin.staging-ws.oat.aws.toyota.com
 
Processing IP: 162.246.76.244
(+) rDNS DISCOVERY! ddc-smtp07.toyota.com
Finished Processing IP: 162.246.76.244
 
Processing domain: staging.sandiego.aws.buyatoyota.com Newly discovered top-level domain: buyatoyota.com Add buyatoyota.com to scope? This will run additional subdomain enumeration (y/n) 
(+) buyatoyota.com ADDED TO SCOPE!
Searching for subdomains of buyatoyota.com. This may take a few seconds...
(+) SUBDOMAIN ENUM DISCOVERY: ADDING TO QUEUE: stage.smartpath.buyatoyota.com
(+) SUBDOMAIN ENUM DISCOVERY: ADDING TO QUEUE: nexus-test.buyatoyota.com
(+) SUBDOMAIN ENUM DISCOVERY: ADDING TO QUEUE: staging.connecticut.buyatoyota.com
(+) SUBDOMAIN ENUM DISCOVERY: ADDING TO QUEUE: westernwashington.buyatoyota.com
(+) SUBDOMAIN ENUM DISCOVERY: ADDING TO QUEUE: staging.static.content.images.aws.buyatoyota.com
(+) SUBDOMAIN ENUM DISCOVERY: ADDING TO QUEUE: origin.www.cincinnati.aws.buyatoyota.com
(+) SUBDOMAIN ENUM DISCOVERY: ADDING TO QUEUE: staging.goldcoast.aws.buyatoyota.com
(+) SUBDOMAIN ENUM DISCOVERY: ADDING TO QUEUE: southernidaho.buyatoyota.com
(+) SUBDOMAIN ENUM DISCOVERY: ADDING TO QUEUE: origin.staging.connecticut.aws.buyatoyota.com
(+) SUBDOMAIN ENUM DISCOVERY: ADDING TO QUEUE: origin.www.set.aws.buyatoyota.com
(+) SUBDOMAIN ENUM DISCOVERY: ADDING TO QUEUE: staging.tristate.aws.buyatoyota.com
(+) SUBDOMAIN ENUM DISCOVERY: ADDING TO QUEUE: www.upstateny.aws.buyatoyota.com
(+) SUBDOMAIN ENUM DISCOVERY: ADDING TO QUEUE: www.denver.aws.buyatoyota.com
(+) SUBDOMAIN ENUM DISCOVERY: ADDING TO QUEUE: origin.staging.centralatlantic.aws.buyatoyota.com
(+) SUBDOMAIN ENUM DISCOVERY: ADDING TO QUEUE: origin.staging.tristateeast.aws.buyatoyota.com
```


Additionally, the –tls flag can be specified to add TLS certificate enumeration. This can be incredibly useful for identifying additional assets, but takes longer to run and is not technically passive reconnaissance as it requests the TLS certificate for each in-scope asset. With Toyota, the –tls flag discovered several additional TLDs and subdomains that were not found using pure DNS enumeration without the –tls flag.

The default settings involve some compromises to achieve the best possible coverage, without diving too deeply down DNS rabbit-holes that have a low probability of finding valid targets. To attempt a more thorough enumeration, the ‘–tlsall’ flag was added. This performs TLS enumeration on ALL identified resources, not just those with TLDs or IP addresses in scope. This flag should be used with caution, as this can often snowball into a huge list of domain names and IP addresses that may not even be remotely associated with your target.

DNSscope Output
---------------

DNSscope outputs a file (default “./DNSscope\_results.txt”) containing each IP address and its associated domains. It organizes the output into assets _explicitly in scope_, _likely in scope_, _out of_ scope, and domains that did not resolve. 

The tool also outputs a log file (default “./output.log”)  that tracks each step of the recon process. The log is updated in real-time and can be useful for determining where a certain subdomain was identified and keeping track of the overall recon process. 

The tool also outputs a log file (default “./output.log”)  that tracks each step of the recon process. The log is updated in real time and can be useful for determining where a certain subdomain was identified and keeping track of the overall recon process. 

Pentesting Tools
----------------

I have personally found this [DNSscope](https://github.com/WhiteOakSecurity/dnsscope) tool very useful for my external network penetration tests. It makes sure I achieve adequate DNS enumeration coverage and makes it easy to discern what is explicitly in scope and not. I plan on actively maintaining the tool and have several features I want to add in the future including the following:

*   CIDR support for the input file.
*   Additional information on newly discovered TLDs to aid in deciding whether to add to scope or not.
*   Multithreading to speed up processing.
*   Check for and alert on Internal IP addresses discovered during recon.

Thanks for reading!

##### **Sources**:

1.  [https://github.com/OWASP/Amass](https://github.com/OWASP/Amass) – Amass GitHub 
2.  [https://github.com/aboul3la/Sublist3r](https://github.com/aboul3la/Sublist3r) – Sublist3r GitHub
3.  [https://github.com/](https://github.com/WhiteOakSecurity/dnsscope)
[WhiteOakSecurity](https://github.com/WhiteOakSecurity/dnsscope)
[/dnsscope](https://github.com/WhiteOakSecurity/dnsscope) – DNSscope GitHub
4.  [https://github.com/](https://github.com/WhiteOakSecurity)
[WhiteOakSecurity](https://github.com/WhiteOakSecurity) – White Oak Security GitHub
