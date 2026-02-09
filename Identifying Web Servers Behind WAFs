# Sneaking Past the Bouncer:Identifying Web Servers Behind WAFs
Oct 28, 2024 10:04:18 AM |

Learn techniques to identify web servers behind Web Application Firewalls (WAFs), bypass middleman security, and uncover potential vulnerabilities in web applications.

Sneaking Past the Bouncer: Identifying Web Servers Behind WAFs

Talis Ozols | June 17, 2024 | Web Application

![](https://blog.cyberadvisors.com/hs-fs/hubfs/image-png-Oct-28-2024-02-59-03-5865-PM.png?width=887&height=590&name=image-png-Oct-28-2024-02-59-03-5865-PM.png)

INTRO
-----

Nearly all web applications these days are utilizing a Web Application Firewall (WAF) to aid in a defense-in-depth approach. WAFs act as a middleman and provide an additional layer of security on top of a web application, using automated technology to help prevent malicious payloads and denial of service attacks from ever even reaching the web server. As penetration testers, we often have our testing IP addresses allowlisted on the WAF so we can achieve solid baseline testing of the underlying web application. Sometimes clients want testing done from the perspective of a true outside attacker including all mitigating controls such as a WAF, and this can create challenges with many payloads being blocked. Oftentimes, a WAF will completely block access to IP addresses that send too many malicious payloads, and from the perspective of an attacker this can be a significant complication requiring WAF bypasses and rotation of IP addresses.

Bypassing the Middleman
-----------------------

In a perfect world, a web server protected by a WAF should not be directly accessible from the outside world. This is often implemented using a restrictive allowlist of IP addresses including the WAF provider’s IP addresses and perhaps the corporate VPN or specific developer source IP addresses for development and testing purposes.

![](https://blog.cyberadvisors.com/hs-fs/hubfs/image-png-Oct-28-2024-02-59-22-0044-PM.png?width=975&height=486&name=image-png-Oct-28-2024-02-59-22-0044-PM.png)

Diagram shows properly configured Web Application Firewall protection preventing direct access

However, it is very common for this allowlist to be misconfigured or nonexistent. Some companies will rely on security-through-obscurity by simply not have a DNS record pointing to the real host. Identifying the unprotected web server can allow unrestricted access to identify and exploit vulnerabilities without needing to develop a WAF bypass. This blog will detail some techniques for identifying these unprotected web servers.

Techniques
----------

#### ENUMERATE CLIENT ASSETS

Oftentimes for web application penetration tests, enumeration of other client assets is overlooked because the rest of their assets are out-of-scope for the engagement. If time allows, TLS and DNS enumeration of the client’s external infrastructure can yield interesting observations about the target web application. Oftentimes it can lead to identifying additional non-production instances of the application that may have debugging or stack traces enabled, additional untested features, or direct access to the target application without a pesky WAF in the way.

Running full DNS enumeration and analysis of TLS certificates for a client network to identify resources is a great way to identify the full scope of the target application environment. I wrote a tool called DNSscope (https://github.com/WhiteOakSecurity/dnsscope) to help with this type of enumeration and asset discovery.

Oftentimes, the real IP address of a web server may be discovered in the following locations:

*   Forward DNS records for non-production instances
    *   e. _targetapp.example.com_ points to the WAF, but subdomain enumeration reveals _stage-targetapp.example.com_ points to the real IP address of the staging and/or production instance.
*   Reverse DNS records
    *   e. forward DNS entries for _targetapp.example.com_ only point to the WAF IP addresses, but running reverse DNS queries against the client’s external IP addresses reveals there is an rDNS entry from an IP address to _targetapp.example.com_.
*   TLS Certificates for client-owned resources
    *   e. Enumeration of a TLS certificate for a web server on a client-owned IP address reveals the certificate is valid for _targetapp.example.com_

#### Historic DNS

Oftentimes companies realize they don’t want the real IP addresses of their web applications in their DNS records, so they set up the WAF and remove the previous DNS records to the real IP address. However, there are several online services that allow access to view historic DNS records. Sometimes we get lucky and this historical data points directly to the real IP address of the target web application.

SecurityTrails (https://securitytrails.com/) is one such service that includes a free option.

![](https://blog.cyberadvisors.com/hs-fs/hubfs/image-png-Oct-28-2024-02-59-43-6091-PM.png?width=975&height=575&name=image-png-Oct-28-2024-02-59-43-6091-PM.png)

Screenshots show SecurityTrails historic DNS data for www.example.com that is no longer present in active DNS records.

#### TLS Certificate Search

In addition to historic DNS data, there are several services that provide access to data on TLS certificates in use by applications and the IP addresses using them. Censys.io ([https://search.censys.io/](https://search.censys.io/)) is one such service and also includes a limited free account option. We can search for our target application to identify any additional hosts that may be using that hostname:

![](https://blog.cyberadvisors.com/hs-fs/hubfs/image-png-Oct-28-2024-02-59-55-6209-PM.png?width=975&height=905&name=image-png-Oct-28-2024-02-59-55-6209-PM.png)

Oftentimes this will just pull up the WAF IP addresses for the application. However, we can then select the “Certificates” search in Censys and search for the certificate in use by the application:

 ![](https://blog.cyberadvisors.com/hs-fs/hubfs/image-png-Oct-28-2024-03-00-07-5669-PM.png?width=974&height=965&name=image-png-Oct-28-2024-03-00-07-5669-PM.png)

Selecting Explore -> “What’s using this certificate” will then reveal all hosts in Censys using this certificate.

 ![](https://blog.cyberadvisors.com/hs-fs/hubfs/image-png-Oct-28-2024-03-00-34-6211-PM.png?width=974&height=827&name=image-png-Oct-28-2024-03-00-34-6211-PM.png)

Oftentimes this will reveal additional IP addresses beyond just doing a hostname search, especially for older certificates or for wildcard certificates.

#### Shodan

Finally, we can use Shodan (https://shodan.io) search to identify additional IP addresses associated with our target application’s hostname or certificate. This can be done with the following two queries in Shodan:

*   cert.subject.cn:targetapp.example.com
*   hostname:targetapp.example.com

![](https://blog.cyberadvisors.com/hs-fs/hubfs/image-png-Oct-28-2024-03-00-42-9249-PM.png?width=975&height=961&name=image-png-Oct-28-2024-03-00-42-9249-PM.png)

For Cloudflare WAF specifically, Badflare (https://github.com/LeeBrotherston/badflare) is a tool that automates identifying the real IP of Cloudflare protected servers using Shodan. However, it currently only supports a hostname search and does not perform the TLS certificate CN search described above.

![](https://blog.cyberadvisors.com/hs-fs/hubfs/image-png-Oct-28-2024-03-00-52-1495-PM.png?width=974&height=566&name=image-png-Oct-28-2024-03-00-52-1495-PM.png)

CONCLUSION
----------

These free resources are helpful in identifying the real IP addresses of web applications behind web application firewalls. Exposing direct access to the web server behind the WAF is a somewhat common misconfiguration and can render expensive WAF solutions completely useless. As penetration testers, getting behind the WAF can be helpful when it is set to blocking, and this issue should be checked for on all web application penetration tests.
