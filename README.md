# My Awesome

[![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)
[![travis-banner](https://travis-ci.org/pe3zx/my-awesome.svg?branch=master)](https://travis-ci.org/pe3zx/my-awesome)

My curated list of awesome links, resources and tools

- [My Awesome](#my-awesome)
- [Articles](#article)
    - [Malware Analysis](#malware-analysis)
    - [Tutorials](#tutorials)
- [Tools](#tools)
	- [AWS Security](#aws-security)
    - [Binary Analysis](#binary-analysis)
    - [Data Exfiltration](#data-exfiltration)
    - [Digital Forensics and Incident Response](#digital-forensics-and-incident-response)
    - [Exploits](#exploits)
    - [Malware Analysis](#malware-analysis-1)
    - [Mobile Securtiy](#mobile-security)
    - [Network](#network)
    - [Plugins](#plugins)
    - [Social Engineering](#social-engineering)
    - [Vulnerable](#vulnerable)
    - [Web Application Security](#web-application-security)
    - [Windows](#windows)

---

## Articles

### Malware Analysis

- CCleaner's backdoor analysis
    - [Protecting the Software Supply Chain: Deep Insights into the CCleaner Backdoor](https://www.crowdstrike.com/blog/protecting-software-supply-chain-deep-insights-ccleaner-backdoor/)
    - [In-Depth Analysis of the CCleaner Backdoor Stage 2 Dropper and Its Payload](https://www.crowdstrike.com/blog/in-depth-analysis-of-the-ccleaner-backdoor-stage-2-dropper-and-its-payload/)
- List of interesting Windows APIs used by malware

<table>
    <tr>
        <td>WNetAddConnection</td>
        <td>The WNetAddConnection function enables the calling application to connect a local device to a network resource. A successful connection is persistent, meaning that the system automatically restores the connection during subsequent logon operations. An example of malware that implement this function can be found below:
            <ul>
                <li><a href="https://securityintelligence.com/new-banking-trojan-icedid-discovered-by-ibm-x-force-research/">Icedid trojan in its network propagation function</a></li>
            </ul>
        </td>
    </tr>
</table>

- Malware analysis environment setup
    - [Knowledge Fragment: Hardening Win7 x64 on VirtualBox for Malware Analysis](http://byte-atlas.blogspot.com/2017/02/hardening-vbox-win7x64.html)

### Tutorials

*This section contains links about tool tutorials, cheat sheet and techniques.*

<table>
    <tr>
        <td>American Fuzzy Lop</td>
        <td>
            <ul>
                <li><a href="https://animal0day.blogspot.co.uk/2017/05/fuzzing-apache-httpd-server-with.html">Fuzzing Apache httpd server with American Fuzzy Lop + persistent mode</a></li>
                <li><a href="https://irssi.org/2017/05/12/fuzzing-irssi/">Fuzzing Irssi</a></li>
                <li><a href="https://symeonp.github.io/2017/09/17/fuzzing-winafl.html">Fuzzing the MSXML6 library with WinAFL</a></li>
                <li><a href="https://www.sec-consult.com/en/blog/2017/09/hack-the-hacker-fuzzing-mimikatz-on-windows-with-winafl-heatmaps-0day/index.html">HACK THE HACKER – FUZZING MIMIKATZ ON WINDOWS WITH WINAFL & HEATMAPS (0DAY)</a></li>
                <li><a href="https://www.softscheck.com/en/identifying-security-vulnerabilities-with-cloud-fuzzing/">How we found a tcpdump vulnerability using cloud fuzzing</a></li>
            </ul>
        </td>
    </tr>
    <tr>
        <td>Binary Ninja</td>
        <td>
            <ul>
                <li><a href="https://blog.trailofbits.com/2016/06/03/2000-cuts-with-binary-ninja/">2000 cuts with Binary Ninja</a></li>
                <li><a href="https://binary.ninja/2017/10/01/automated-opaque-predicate-removal.html">Automated Opaque Predicate Removal</a></li>
                <li><a href="http://www.chokepoint.net/2017/10/pin-visual-coverage-tool-for-binary.html">Pin Visual Coverage Tool For Binary Ninja</a></li>
                <li><a href="https://blog.ret2.io/2017/10/17/untangling-exotic-architectures-with-binary-ninja/">Untangling Exotic Architectures with Binary Ninja</a></li>
            </ul>
        </td>
    </tr>
    <tr>
        <td>BloodHound</td>
        <td>
            <ul>
                <li><a href="http://threat.tevora.com/lay-of-the-land-with-bloodhound/">Lay of the Land with BloodHound</a></li>
            </ul>
        </td>
    </tr>
    <tr>
        <td>Docker</td>
        <td>
            <ul>
                <li><a href="https://hackernoon.com/making-right-things-using-docker-7296cf0f6c6e">Making right things using Docker</a></li>
            </ul>
        </td>
    </tr>
    <tr>
        <td>Elasticsearch</td>
        <td>
            <ul>
                <li><a href="https://www.elastic.co/blog/a-practical-introduction-to-elasticsearch">A Practical Introduction to Elasticsearch</a></li>
            </ul>
        </td>
    </tr>
    <tr>
        <td>Frida</td>
        <td>
            <ul>
                <li><a href="http://www.fuzzysecurity.com/tutorials/29.html">Application Introspection & Hooking With Frida</a></li>
            </ul>
        </td>
    </tr>
    <tr>
        <td>IDA Pro</td>
        <td>
            <ul>
                <li><a href="https://qmemcpy.github.io/post/ida-series-1-hex-rays">IDA series, part 1: the Hex-Rays decompiler</a></li>
                <li><a href="https://qmemcpy.github.io/post/ida-series-2-debugging-net">IDA series, part 2: debugging a .NET executable</a></li>
            </ul>
        </td>
    </tr>
    <tr>
        <td>Masscan</td>
        <td>
            <ul>
                <li><a href="https://danielmiessler.com/study/masscan/#gs.zhlnvjE">A Masscan Tutorial and Primer</a></li>
            </ul>
        </td>
    </tr>
    <tr>
        <td>osquery</td>
        <td>
            <ul>
                <li><a href="https://blog.trailofbits.com/2017/10/10/tracking-a-stolen-code-signing-certificate-with-osquery/">Tracking a stolen code-signing certificate with osquery</a></li>
                <li><a href="https://medium.com/@palantir/osquery-across-the-enterprise-3c3c9d13ec55">osquery Across the Enterprise</a></li>
            </ul>
        </td>
    </tr>
    <tr>
        <td>RunPE</td>
        <td>
            <ul>
                <li><a href="https://www.adlice.com/runpe-hide-code-behind-legit-process/">RunPE: How to hide code behind a legit process</a></li>
            </ul>
        </td>
    </tr>
    <tr>
        <td>Splunk</td>
        <td>
            <ul>
                <li><a href="https://www.malwarearchaeology.com/s/Windows-Splunk-Logging-Cheat-Sheet-v20-spjb.pdf">The Windows Splunk Logging Cheat Sheet</a></li>
            </ul>
        </td>
    </tr>
    <tr>
        <td>Sysmon</td>
        <td>
            <ul>
                <li><a href="http://www.hexacorn.com/blog/2017/10/02/sysmon-doing-lines/">Sysmon doing lines</a></li>
                <li><a href="https://github.com/MHaggis/sysmon-dfir">Mhaggis/sysmon-dfir</a></li>
                <li><a href="http://syspanda.com/index.php/2017/02/28/deploying-sysmon-through-gpo/">Deploying Sysmon through Group Policy (GPO)</a></li>
                <li><a href="http://syspanda.com/index.php/2017/03/03/sysmon-filtering-using-logstash/">Advanced Sysmon filtering using Logstash</a></li>
                <li><a href="http://syspanda.com/index.php/2017/10/10/threat-hunting-sysmon-word-document-macro/">Threat Hunting with Sysmon: Word Document with Macro</a></li>
                <li><a href="http://syspanda.com/index.php/2017/10/31/monitoring-monitor-sysmon-status/">Monitoring the monitor: Sysmon status</a></li>
            </ul>
        </td>
    </tr>
    <tr>
        <td>Radare2</td>
        <td>
            <ul>
                <li><a href="https://www.megabeets.net/a-journey-into-radare-2-part-1/">A journey into Radare 2 – Part 1: Simple crackme</a></li>
                <li><a href="https://www.megabeets.net/a-journey-into-radare-2-part-2/">A journey into Radare 2 – Part 2: Exploitation</a></li>
                <li><a href="http://blog.superponible.com/2017/04/15/emulating-assembly-in-radare2/">Emulating Assembly in Radare2</a></li>
                <li><a href="https://github.com/chrysh/ctf_writeups/tree/master/pwnable.kr">Pwnable.kr - Passcode</a></li>
                <li><a href="https://monosource.github.io/2016/10/radare2-peda">radare2 as an alternative to gdb-peda</a></li>
            </ul>
        </td>
    </tr>
    <tr>
        <td>Volatility</td>
        <td>
            <ul>
                <li><a href="https://andreafortuna.org/volatility-my-own-cheatsheet-part-1-image-identification-9343c077f8da">Volatility, my own cheatsheet (Part 1): Image Identification</a></li>
                <li><a href="https://andreafortuna.org/volatility-my-own-cheatsheet-part-2-processes-and-dlls-ba22050ba25a">Volatility, my own cheatsheet (Part 2): Processes and DLLs</a></li>
                <li><a href="https://andreafortuna.org/volatility-my-own-cheatsheet-part-3-process-memory-a0470f378ad2">Volatility, my own cheatsheet (Part 3): Process Memory</a></li>
                <li><a href="https://andreafortuna.org/volatility-my-own-cheatsheet-part-4-kernel-memory-and-objects-af9c022bf32c">Volatility, my own cheatsheet (Part 4): Kernel Memory and Objects</a></li>
                <li><a href="https://andreafortuna.org/volatility-my-own-cheatsheet-part-5-networking-ae92834e2214">Volatility, my own cheatsheet (Part 5): Networking</a></li>
                <li><a href="https://andreafortuna.org/volatility-my-own-cheatsheet-part-6-windows-registry-ddbea0e15ff5">Volatility, my own cheatsheet (Part 6): Windows Registry</a></li>
                <li><a href="https://andreafortuna.org/volatility-my-own-cheatsheet-part-7-analyze-and-convert-crash-dumps-and-hibernation-files-5d4b5b9c5194">Volatility, my own cheatsheet (Part 7): Analyze and convert crash dumps and hibernation files</a></li>
                <li><a href="https://andreafortuna.org/volatility-my-own-cheatsheet-part-8-filesystem-5c1b710b091f">Volatility, my own cheatsheet (Part 8): Filesystem</a></li>
                <li><a href="https://isc.sans.edu/forums/diary/Using+Yara+rules+with+Volatility/22950/">Using Yara rules with Volatility</a></li>
            </ul>
        </td>
    </tr>
    <tr>
        <td>WinDBG</td>
        <td>
            <ul>
                <li><a href="https://vallejo.cc/2017/07/16/anti-antidebugging-windbg-scripts/">Anti-Antidebugging WinDbg Scripts</a></li>
                <li><a href="https://github.com/bulentrahimkazanci/Windbg-Cheat-Sheet">bulentrahimkazanci/Windbg-Cheat-Sheet</a></li>
                <li><a href="http://blog.talosintelligence.com/2017/08/windbg-and-javascript-analysis.html">WinDBG and JavaScript Analysis</a></li>
            </ul>
        </td>
    </tr>
</table>

## Tools

### AWS Security

*Open source projects related to AWS security.*

<table>
    <tr>
        <td>
            <a href="https://github.com/airbnb/BinaryAlert" target="_blank">airbnb/BinaryAlert</a>
        </td>
        <td>
            BinaryAlert: Serverless, Real-time & Retroactive Malware Detection
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/cloudsploit/scans" target="_blank">cloudsploit/scans</a>
        </td>
        <td>
            AWS security scanning checks
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/nccgroup/Scout2" target="_blank">nccgroup/Scout2</a>
        </td>
        <td>
            Security auditing tool for AWS environments
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/Netflix/security_monkey" target="_blank">Netflix/security_monkey</a>
        </td>
        <td>
            Security Monkey monitors your AWS and GCP accounts for policy changes and alerts on insecure configurations.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/Alfresco/prowler" target="_blank">Alfresco/prowler</a>
        </td>
        <td>
            Tool for AWS security assessment, auditing and hardening. It follows guidelines of the CIS Amazon Web Services Foundations Benchmark.
        </td>
    </tr>
</table>

### Binary Analysis

*Binary analysis tools, including decompilers, deobfuscators, disassemblers, etc.*

<table>
    <tr>
        <td><a href="https://github.com/enkomio/shed">enkomio/shed</a></td>
        <td>.NET runtine inspector. <a href="http://antonioparata.blogspot.it/2017/11/shed-inspect-net-malware-like-sir.html">Shed - Inspect .NET malware like a Sir</a></td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/fireeye/flare-floss">fireeye/flare-floss</a>
        </td>
        <td>
            FireEye Labs Obfuscated String Solver - Automatically extract obfuscated strings from malware.
        </td>
    </tr>
    <tr>
        <td><a href="https://lief.quarkslab.com/">LIEF</a></td>
        <td>Library to Instrument Executable Formats</td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/williballenthin/python-idb">williballenthin/python-idb</a>
        </td>
        <td>
            Pure Python parser and analyzer for IDA Pro database files (.idb).
        </td>
    </tr>
</table>

### Data Exfiltration

*Tools related to data exfiltration and covert channels*

<table>
    <tr>
        <td><a href="https://github.com/evilsocket/sg1">evilsocket/sg1</a></td>
        <td>A wanna be swiss army knife for data encryption, exfiltration and covert communication.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/pentestpartners/PTP-RAT">pentestpartners/PTP-RAT</a></td>
        <td>Exfiltrate data over screen interfaces. <a href="https://www.pentestpartners.com/security-blog/exfiltration-by-encoding-data-in-pixel-colour-values/">For more information.</a></td>
    </tr>
    <tr>
        <td><a href="https://github.com/sensepost/DET">sensepost/DET</a></td>
        <td>DET (is provided AS IS), is a proof of concept to perform Data Exfiltration using either single or multiple channel(s) at the same time.</td>
    </tr>
</table>

### DevOps

*DevSecOps stuff, or SevDevOps, or DevOpsSec, or SecDevSecOpsSec!?*

<table>
    <tr>
        <td><a href="https://github.com/GoogleCloudPlatform/container-diff">GoogleCloudPlatform/container-diff</a></td>
        <td>container-diff is a tool for analyzing and comparing container images. container-diff can examine images along several different criteria, including: Docker Image History, Image file system, packages, etc.</td>
    </tr>
</table>

### Digital Forensics and Incident Response

*Open source projects related to DFIR topic.*

<table>
    <tr>
        <td><a href="https://github.com/intezer/linux-explorer">intezer/linux-explorer</a></td>
        <td>Easy-to-use live forensics toolbox for Linux endpoints</td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/Invoke-IR/PowerForensics">Invoke-IR/PowerForensics</a>
        </td>
        <td>
            PowerForensics provides an all in one platform for live disk forensic analysis
        </td>
    </tr>
    <tr>
        <td><a href="https://github.com/MalwareSoup/MitreAttack">MalwareSoup/MitreAttack</a></td>
        <td>Python wrapper for the Mitre ATT&CK framework API</td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/nannib/Imm2Virtual">nannib/Imm2Virtual</a>
        </td>
        <td>
            This is a GUI (for Windows 64 bit) for a procedure to virtualize your EWF(E01), DD(Raw), AFF disk image file without converting it, directly with VirtualBox, forensically proof.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/nshalabi/SysmonTools">nshalabi/SysmonTools</a>
        </td>
        <td>
            Utilities for Sysmon (Sysmon View and Sysmon Shell)
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/THIBER-ORG/userline">THIBER-ORG/userline</a>
        </td>
        <td>
            Query and report user logons relations from MS Windows Security Events
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/TryCatchHCF/DumpsterFire">TryCatchHCF/DumpsterFire</a>
        </td>
        <td>
            "Security Incidents In A Box!" A modular, menu-driven, cross-platform tool for building customized, time-delayed, distributed security events. Easily create custom event chains for Blue Team drills and sensor / alert mapping. Red Teams can create decoy incidents, distractions, and lures to support and scale their operations. Build event sequence…
        </td>
    </tr>
</table>

### Exploits

*Interesting exploits. For research purpose only*

<table>
    <tr>
        <td>CVE-2016-7255</td>
        <td>The kernel-mode drivers in Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, Windows 10 Gold, 1511, and 1607, and Windows Server 2016 allow local users to gain privileges via a crafted application, aka "Win32k Elevation of Privilege Vulnerability."
            <ul>
                <li><a href="https://github.com/IOActive/I-know-where-your-page-lives">IOActive/I-know-where-your-page-lives</a></li>
            </ul>
        </td>
    </tr>
    <tr>
        <td>CVE-2017-5123</td>
        <td>The `waitid` implementation in upstream kernels did not restrict the target destination to copy information results. This can allow local users to write to     otherwise protected kernel memory, which can lead to privilege escalation.
            <ul>
                <li><a href="https://github.com/nongiach/CVE/tree/master/CVE-2017-5123">nongiach/CVE</a></li>
            </ul>
        </td>
    </tr>
    <tr>
        <td>CVE-2017-7089</td>
        <td>
            A logic issue existed in the handling of the parent-tab. This issue was addressed with improved state management. Processing maliciously crafted web content may lead to universal cross site scripting.
            <ul>
                <li><a href="https://github.com/Bo0oM/CVE-2017-7089">Bo0oM/CVE-2017-7089</a></li>
            </ul>
        </td>
    </tr>
    <tr>
        <td>CVE-2017-7115</td>
        <td>
        The exploit achieves R/W access to the host's physical memory. The password for the archive is "one_ring". This exploit has been tested on the iPhone 7, iOS 10.2 (14C92). To run the exploit against different devices or versions, the symbols must be adjusted.
            <ul>
                <li><a href="https://bugs.chromium.org/p/project-zero/issues/detail?id=1317#c3">Apple: Multiple Race Conditions in PCIe Message Ring protocol leading to OOB Write and OOB Read</a></li>
            </ul>
        </td>
    </tr>
    <tr>
        <td>CVE-2017-8464</td>
        <td>Windows Shell in Microsoft Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, Windows 10 Gold, 1511, 1607, 1703, and Windows Server 2016 allows local users or remote attackers to execute arbitrary code via a crafted .LNK file, which is not properly handled during icon display in Windows Explorer or any other application that parses the icon of the shortcut. aka "LNK Remote Code Execution Vulnerability."
            <ul>
                <li><a href="https://www.exploit-db.com/exploits/42429/">CVE-2017-8464 - Microsoft Windows - '.LNK' Shortcut File Code Execution</a></li>
            </ul>
        </td>
    </tr>
    <tr>
        <td>CVE-2017-8759</td>
        <td>Microsoft .NET Framework 2.0, 3.5, 3.5.1, 4.5.2, 4.6, 4.6.1, 4.6.2 and 4.7 allow an attacker to execute code remotely via a malicious document or application, aka ".NET Framework Remote Code Execution Vulnerability."
            <ul>
                <li><a href="https://github.com/fupinglee/MyPython/blob/master/exploit/CVE-2017-8759/CVE-2017-8759_exploit_rtf.py">MyPython/exploit/CVE-2017-8759/CVE-2017-8759_exploit_rtf.py</a></li>
                <li><a href="https://github.com/vysec/CVE-2017-8759">vysec/CVE-2017-8759</a></li>
                <li><a href="https://twitter.com/PayloadSecurity/status/907911356460027904">CVE-2017-8759 - Malware Sample</a>
            </ul>
        </td>
    </tr>
    <tr>
        <td>CVE-2017-11882</td>
        <td>Microsoft Office 2007 Service Pack 3, Microsoft Office 2010 Service Pack 2, Microsoft Office 2013 Service Pack 1, and Microsoft Office 2016 allow an attacker to run arbitrary code in the context of the current user by failing to properly handle objects in memory, aka "Microsoft Office Memory Corruption Vulnerability". This CVE ID is unique from CVE-2017-11884.
            <ul>
                <li><a href="https://github.com/embedi/CVE-2017-11882">embedi/CVE-2017-11882</a></li>
                <li><a href="https://twitter.com/hybridanalysis/status/932954160395444230">Sample of malware used CVE-2017-11882</a></li>
            </ul>
        </td>
    </tr>
    <tr>
        <td>CVE-2017-13082</td>
            <td>Wi-Fi Protected Access (WPA and WPA2) that supports IEEE 802.11r allows reinstallation of the Pairwise Transient Key (PTK) Temporal Key (TK) during the fast BSS transmission (FT) handshake, allowing an attacker within radio range to replay, decrypt, or spoof frames.
                <ul>
                    <li><a href="https://www.krackattacks.com">the KRACK attack website</a></li>
                    <li><a href="https://papers.mathyvanhoef.com/ccs2017.pdf">KRACK attack research paper</a></li>
                    <li><a href="https://github.com/vanhoefm/krackattacks-test-ap-ft">vanhoefm/krackttacks-test-ap-ft</a></li>
                </ul>
            </td>
    </tr>
    <tr>
        <td><a href="https://github.com/FriendsOfPHP/security-advisories">FriendsOfPHP/security-advisories</a></td>
        <td>The PHP Security Advisories Database references known security vulnerabilities in various PHP projects and libraries. This database must not serve as the primary source of information for security issues, it is not authoritative for any referenced software, but it allows to centralize information for convenience and easy consumption.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ScottyBauer/Android_Kernel_CVE_POCs">ScottyBauer/Android_Kernel_CVE_POCs</a></td>
        <td>A list of my CVE's with POCs</td>
    </tr>
    <tr>
        <td><a href="https://github.com/spencerdodd/kernelpop">spencerdodd/kernelpop</a></td>
        <td>Kernel privilege escalation enumeration and exploitation framework</td>
    </tr>
    <tr>
        <td><a href="https://github.com/tunz/js-vuln-db">tunz/js-vuln-db</a></td>
        <td>A collection of JavaScript engine CVEs with PoCs</td>
    </tr>
    <tr>
        <td><a href="https://github.com/victims/victims-cve-db">victims/victims-cve-db</a></td>
        <td>This database contains information regarding CVE(s) that affect various language modules. We currently store version information corresponding to respective modules as understood by select sources.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/xairy/kernel-exploits">xairy/kernel-exploits</a></td>
        <td>A bunch of proof-of-concept exploits for the Linux kernel</td>
    </tr>
</table>

### Malware Analysis

*Tools related to malware analysis, malware development (for research purpose) and malware sample finding*

<table>
    <tr>
        <td><a href="https://github.com/adamkramer/rapid_env">adamkramer/rapid_env</a></td>
        <td>Rapid deployment of Windows environment (files, registry keys, mutex etc) to facilitate malware analysis</td>
    </tr>
    <tr>
        <td><a href="https://www.malwaretracker.com/doc.php">Cryptam Document Scanner</a></td>
        <td>Encrypted/obfuscated malicious document analyzer</td>
    </tr>
    <tr>
        <td><a href="http://dasmalwerk.eu/">DAS MALWERK</a></td>
        <td>DAS MALWERK - your one stop shop for fresh malware samples</td>
    </tr>
    <tr>
        <td><a href="https://certsocietegenerale.github.io/fame/">FAME</a></td>
        <td>FAME Automates Malware Evaluation</td>
    </tr>
    <tr>
        <td><a href="https://github.com/hasherezade/libpeconv/tree/master/run_pe">hasherezade/libpeconv/runpe</a></td>
        <td>RunPE (aka Process Hollowing) is a well known technique allowing to injecting a new PE into a remote processes, imprersonating this process. The given implementation works for PE 32bit as well as 64bit.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/hegusung/AVSignSeek">hegusung/AVSignSeek</a></td>
        <td>Tool written in python3 to determine where the AV signature is located in a binary/payload</td>
    </tr>
    <tr>
        <td><a href="https://iris-h.malwageddon.com/">IRIS-H</a></td>
        <td>IRIS-H is an online digital forensics tool that performs automated static analysis of files stored in a directory-based or strictly structured formats.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/katjahahn/PortEx">katjahahn/PortEx</a></td>
        <td>Java library to analyse Portable Executable files with a special focus on malware analysis and PE malformation robustness</td>
    </tr>
    <tr>
        <td><a href="https://github.com/LordNoteworthy/al-khaser">LordNoteworthy/al-khaser</a></td>
        <td>Public malware techniques used in the wild: Virtual Machine, Emulation, Debuggers, Sandbox detection.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/nsmfoo/antivmdetection">nsmfoo/antivmdetection</a></td>
        <td>Script to create templates to use with VirtualBox to make vm detection harder</td>
    </tr>
    <tr>
        <td><a href="https://github.com/OALabs/BlobRunner">OALabs/BlobRunner</a></td>
        <td>Quickly debug shellcode extracted during malware analysis</td>
    </tr>
    <tr>
        <td><a href="https://github.com/quasar/QuasarRAT">quasar/QuasarRAT</a></td>
        <td>Quasar is a fast and light-weight remote administration tool coded in C#. Providing high stability and an easy-to-use user interface, Quasar is the perfect remote administration solution for you.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/GoSecure/malboxes">GoSecure/malboxes</a></td>
        <td>Builds malware analysis Windows VMs so that you don't have to.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/SafeBreach-Labs/mkmalwarefrom">SafeBreach-Labs/mkmalwarefrom</a></td>
        <td>Proof-of-concept two-stage dropper generator that uses bits from external sources</td>
    </tr>
    <tr>
        <td><a href="https://malware.sekoia.fr/new">SEKOIA Dropper Analysis</a></td>
        <td>SEKOIA Dropper Analysis</td>
    </tr>
</table>

### Mobile Security

*Tools related to mobile security, mobile application auditing/debugging and mobile penetration testing*

<table>
    <tr>
        <td><a href="https://github.com/dpnishant/appmon">dpnishant/appmon</a></td>
        <td>AppMon is an automated framework for monitoring and tampering system API calls of native macOS, iOS and android apps. It is based on Frida.</td>
    </tr>
    <tr>
        <td><a href="https://www.htbridge.com/mobile">Mobile X-Ray</a></td>
        <td>Just upload your iOS or Android mobile app to start a DAST, SAST and behavioral audit for OWASP Mobile Top 10 and other vulnerabilities</td>
    </tr>
</table>

### Network

*Network and network security related tools*

<table>
    <tr>
        <td><a href="https://github.com/michenriksen/aquatone">michenriksen/aquatone</a></td>
        <td>AQUATONE is a set of tools for performing reconnaissance on domain names. It can discover subdomains on a given domain by using open sources as well as the more common subdomain dictionary brute force approach. After subdomain discovery, AQUATONE can then scan the hosts for common web ports and HTTP headers, HTML bodies and screenshots can be gathered and consolidated into a report for easy analysis of the attack surface.</td>
    </tr>
    <tr>
        <td><a href="https://packettotal.com/">PacketTotal</a></td>
        <td>A free, online PCAP analysis engine</td>
    </tr>
    <tr>
        <td><a href="https://wireedit.com/">WireEdit</a></td>
        <td>First-Of-A-Kind And The Only Full Stack WYSIWYG Pcap Editor</td>
    </tr>
</table>

### Password Tools

*Tools related to password cracking, bruteforcing and also wordlists*

<table>
    <tr>
        <td><a href="https://github.com/fireeye/gocrack">fireeye/gocrack</a></td>
        <td>GoCrack provides APIs to manage password cracking tasks across supported cracking engines.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/sc0tfree/mentalist">sc0tfree/mentalist</a></td>
        <td>Mentalist is a graphical tool for custom wordlist generation. It utilizes common human paradigms for constructing passwords and can output the full wordlist as well as rules compatible with Hashcat and John the Ripper.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/danielmiessler/SecLists">danielmiessler/SecLists</a></td>
        <td>SecLists is the security tester's companion. It is a collection of multiple types of lists used during security assessments. List types include usernames, passwords, URLs, sensitive data grep strings, fuzzing payloads, and many more.</td>
    </tr>
</table>

### Plugins

*Plugins and extensions for tools*

<table>
    <tr>
        <td colspan="2"><b>Burp Suite</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/lightbulb-framework/lightbulb-framework">lightbulb-framework/lightbulb-framework</a></td>
        <td>LightBulb is an open source python framework for auditing web application firewalls and filters.</td>
    </tr>
    <tr>
        <td colspan="2"><b>GDB</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/cs01/gdbgui">cs01/gdbgui</a></td>
        <td>Browser-based frontend to gdb (gnu debugger). Add breakpoints, view the stack, visualize data structures, and more in C, C++, Go, Rust, and Fortran. Run gdbgui from the terminal and a new tab will open in your browser.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cyrus-and/gdb-dashboard">cyrus-and/gdb-dashboard</a></td>
        <td>Modular visual interface for GDB in Python</td>
    </tr>
    <tr>
        <td><a href="https://github.com/longld/peda">longld/peda</a></td>
        <td>PEDA - Python Exploit Development Assistance for GDB</td>
    </tr>
    <tr>
        <td colspan="2"><b>IDA Pro</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/gaasedelen/lighthouse">gaasedelen/lighthouse</a></td>
        <td>Lighthouse is a code coverage plugin for IDA Pro. The plugin leverages IDA as a platform to map, explore, and visualize externally collected code coverage data when symbols or source may not be available for a given binary.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/hasherezade/ida_ifl">hasherezade/ida_ifl</a></td>
        <td>IFL - Interactive Functions List (plugin for IDA Pro)</td>
    </tr>
    <tr>
        <td><a href="https://github.com/onethawt/idaplugins-list">onethawt/idaplugins-list</a></td>
        <td>A list of IDA Plugins</td>
    </tr>
    <tr>
        <td colspan="2"><b>WinDBG</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/comaeio/SwishDbgExt">comaeio/SwishDbgExt</a></td>
        <td>Incident Response & Digital Forensics Debugging Extension</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Microsoft/DbgShell">Microsoft/DbgShell</a></td>
        <td>A PowerShell front-end for the Windows debugger engine.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/swwwolf/wdbgark">swwwolf/wdbgark</a></td>
        <td>WinDBG Anti-RootKit Extension</td>
    </tr>
</table>

### Social Engineering

*Tools related to social engineering attack, OSINT and human hacking*

<table>
    <tr>
        <td><a href="https://github.com/boxug/trape">boxug/trape</a></td>
        <td>People tracker on the Internet: Learn to track the world, to avoid being traced.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/dafthack/MailSniper">dafthack/MailSniper</a></td>
        <td>MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords, insider intel, network architecture information, etc.). It can be used as a non-administrative user to search their own email, or by an administrator to search the mailboxes of every user in a domain.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/DataSploit/datasploit">DataSploit/datasploit</a></td>
        <td>An #OSINT Framework to perform various recon techniques on Companies, People, Phone Number, Bitcoin Addresses, etc., aggregate all the raw data, and give data in multiple formats.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/securestate/king-phisher/">securestate/king-phisher</a></td>
        <td>Phishing Campaign Toolkit</td>
    </tr>
    <tr>
        <td><a href="http://www.spiderfoot.net/">SpiderFoot</a></td>
        <td>SpiderFoot - Opensource Intelligence Automation</td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/UndeadSec/EvilURL">Undeadsec/EvilURL</a>
        </td>
        <td>
            An unicode domain phishing generator for IDN Homograph Attack
        </td>
    </tr>
    <tr>
        <td><a href="https://github.com/ustayready/CredSniper">ustayready/CredSniper</a></td>
        <td>CredSniper is a phishing framework written with the Python micro-framework Flask and Jinja2 templating which supports capturing 2FA tokens.</td>
    </tr>
</table>

### Vulnerable

*Vulnerable software, application, VM for research purpose*

<table>
    <tr>
        <td><a href="https://github.com/cliffe/SecGen">cliffe/SecGen</a></td>
        <td>SecGen creates vulnerable virtual machines so students can learn security penetration testing techniques.</td>
    </tr>
    <tr>
        <td><a href="https://tuts4you.com/download.php?list.17">Lenas Reversing for Newbies</a></td>
        <td>Nice collection of tutorials aimed particularly for newbie reverse enginners...</td>
    </tr>
    <tr>
        <td><a href="https://www.notsosecure.com/vulnerable-docker-vm/">Vulnerable Docker VM</a></td>
        <td>Ever fantasized about playing with docker misconfigurations, privilege escalation, etc. within a container?</td>
    </tr>
</table>

### Web Application Security

*Web application security tools*

<table>
    <tr>
        <td><a href="https://github.com/appsecco/spaces-finder">appsecco/spaces-finder</a></td>
        <td>A tool to hunt for publicly accessible DigitalOcean Spaces</td>
    </tr>
    <tr>
        <td><a href="https://github.com/anantshri/svn-extractor">anatshri/svn-extractor</a></td>
        <td>Simple script to extract all web resources by means of .SVN folder exposed over network.</td>
    </tr>
    <tr>
        <td><a href="https://illuminatejs.com">IlluminateJs</a></td>
        <td>IlluminateJs is a static javascript analysis engine (a deobfuscator so to say) aimed to help analyst understand obfuscated and potentially malicious JavaScript Code.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mazen160/bfac">mazen160/bfac</a></td>
        <td>BFAC (Backup File Artifacts Checker): An automated tool that checks for backup artifacts that may disclose the web-application's source code.</td>
    </tr>
</table>

### Windows

*Tools for Windows only*

<table>
    <tr>
        <td><a href="https://github.com/api0cradle/UltimateAppLockerByPassList">api0cradle/UltimateAppLockerByPassList</a></td>
        <td>The goal of this repository is to document the most common techniques to bypass AppLocker.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/google/sandbox-attacksurface-analysis-tools">google/sandbox-attacksurface-analysis-tools</a></td>
        <td>This is a small suite of tools to test various properties of sandboxes on Windows. Many of the checking tools take a -p flag which is used to specify the PID of a sandboxed process. The tool will impersonate the token of that process and determine what access is allowed from that location. Also it's recommended to run these tools as an administrator or local system to ensure the system can be appropriately enumerated.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/hlldz/Invoke-Phant0m">hlldz/Invoke-Phant0m</a></td>
        <td>Windows Event Log Killer</td>
    </tr>
    <tr>
        <td><a href="https://github.com/jonatan1024/clrinject">jonatan1024/clrinject</a></td>
        <td>Injects C# EXE or DLL Assembly into every CLR runtime and AppDomain of another process.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/sevagas/macro_pack">sevagas/macro_pack</a></td>
        <td>macro_pack is a tool used to automatize obfuscation and generation of MS Office documents for pentest, demo, and social engineering assessments. The goal of macro_pack is to simplify antimalware bypass and automatize the process from vba generation to final Office document generation.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Plazmaz/LNKUp">Plazmaz/LNKUp</a></td>
        <td>Generates malicious LNK file payloads for data exfiltration</td>
    </tr>
    <tr>
        <td><a href="https://github.com/secretsquirrel/SigThief">secretsquirrel/SigThief</a></td>
        <td>Stealing Signatures and Making One Invalid Signature at a Time</td>
    </tr>
</table>
