# My Infosec Awesome <!-- omit in toc -->

<p align="center">
  <img src="cover.png">
</p>

<p align="center"><img src="https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg" /> <a href="https://github.com/pe3zx/my-infosec-awesome/actions"><img src="https://github.com/pe3zx/my-infosec-awesome/workflows/Ruby/badge.svg" /></a> <img src="https://img.shields.io/github/last-commit/pe3zx/my-infosec-awesome.svg"/> </p>

This repository is created as an online bookmark for useful links, resources and tools in infosec field which serve my needs to have a searchable page to look further.

- [Adversary Simulation & Emulation](#adversary-simulation--emulation)
- [Application Security](#application-security)
- [Binary Analysis](#binary-analysis)
- [Cloud Security](#cloud-security)
- [Courses](#courses)
- [Cryptography](#cryptography)
- [Data Exfiltration](#data-exfiltration)
- [Data Sets](#data-sets)
- [Digital Forensics and Incident Response](#digital-forensics-and-incident-response)
- [Exploits](#exploits)
- [Hardening](#hardening)
- [Hardware](#hardware)
- [Malware Analysis](#malware-analysis)
- [Mobile Security](#mobile-security)
- [Network Security](#network-security)
- [Open-source Intelligence (OSINT)](#open-source-intelligence-osint)
- [Password Cracking and Wordlists](#password-cracking-and-wordlists)
- [Post Exploitation](#post-exploitation)
- [Social Engineering](#social-engineering)
- [Vulnerable](#vulnerable)

## Adversary Simulation & Emulation

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/alphasoc/flightsim">alphasoc/flightsim</a></td>
        <td>A utility to generate malicious network traffic and evaluate controls</td>
    </tr>
    <tr>
        <td><a href="https://docs.microsoft.com/en-us/office365/securitycompliance/attack-simulator">Attack Simulatorin Office 365</a></td>
        <td>Simulate realistic attacks on Office 365 environment</td>
    </tr>
    <tr>
        <td><a href="https://www.encripto.no/en/downloads-2/tools/">Blue Team Training Toolkit</a></td>
        <td>Blue Team Training Toolkit (BT3) is designed for network analysis training sessions, incident response drills and red team engagements</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Coalfire-Research/Red-Baron">Coalfire-Research/Red-Baron</a></td>
        <td>Automate creating resilient, disposable, secure and agile infrastructure for Red Teams</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Cyb3rWard0g/Invoke-ATTACKAPI">Cyb3rWard0g/Invoke-ATTACKAPI</a></td>
        <td>A PowerShell script to interact with the MITRE ATT&CK Framework via its own API</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Cyb3rWard0g/mordor">Cyb3rWard0g/mordor</a></td>
        <td>Re-play Adversarial Techniques</td>
    </tr>
    <tr>
        <td><a href="https://github.com/chryzsh/DarthSidious/">chryzsh/DarthSidious</a></td>
        <td>Building an Active Directory domain and hacking it</td>
    </tr>
	<tr>
		<td><a href="https://github.com/d3vzer0/reternal-quickstart">d3vzer0/reternal-quickstart</a></td>
		<td>Repo containing docker-compose files and setup scripts without having to clone the individual reternal components</td>
	</tr>
    <tr>
        <td><a href="https://github.com/ElevenPaths/ATTPwn">ElevenPaths/ATTPwn</a></td>
        <td>ATTPwn is a computer security tool designed to emulate adversaries.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/endgameinc/RTA">endgameinc/RTA</a></td>
        <td>RTA provides a framework of scripts designed to allow blue teams to test their detection capabilities against malicious tradecraft, modeled after MITRE ATT&CK</td>
    </tr>
    <tr>
        <td><a href="https://github.com/fireeye/capa">fireeye/capa</a></td>
        <td>capa detects capabilities in executable files. You run it against a PE file or shellcode and it tells you what it thinks the program can do. For example, it might suggest that the file is a backdoor, is capable of installing services, or relies on HTTP to communicate.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/fireeye/capa-rules">fireeye/capa-rules</a></td>
        <td>Standard collection of rules for capa: the tool for enumerating the capabilities of programs</td>
    </tr>
    <tr>
        <td><a href="https://github.com/jymcheong/AutoTTP">jymchoeng/AutoTTP</a></td>
        <td>Automated Tactics Techniques & Procedures</td>
    </tr>
    <tr>
        <td><a href="https://github.com/MiladMSFT/ThreatHunt">MiladMSFT/ThreatHunt</a></td>
        <td>ThreatHunt is a PowerShell repository that allows you to train your threat hunting skills.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mdsecactivebreach/CACTUSTORCH">mdsecactivebreach/CACTUSTORCH</a></td>
        <td>CACTUSTORCH: Payload Generation for Adversary Simulations</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mitre/caldera">mitre/caldera</a></td>
        <td>An automated adversary emulation system</td>
    </tr>
    <tr>
        <td><a href="https://github.com/NextronSystems/APTSimulator">NextronSystems/APTSimulator</a></td>
        <td>A toolset to make a system look as if it was the victim of an APT attack</td>
    </tr>
    <tr>
        <td><a href="https://github.com/n0dec/MalwLess">n0dec/MalwLess</a></td>
        <td>Test blue team detections without running any attack</td>
    </tr>
	<tr>
		<td><a href="https://github.com/OTRF/SimuLand">OTRF/SimuLand</a></td>
		<td>Cloud Templates and scripts to deploy mordor environments</a></td>
	</tr>
	<tr>
		<td><a href="https://github.com/praetorian-code/purple-team-attack-automation">praetorian-code/purple-team-attack-automation</a></td>
		<td>Praetorian's public release of our Metasploit automation of MITRE ATT&CK™ TTPs</td>
	</tr>
    <tr>
        <td><a href="https://github.com/TryCatchHCF/DumpsterFire">TryCatchHCF/DumpsterFire</a></td>
        <td>"Security Incidents In A Box!" A modular, menu-driven, cross-platform tool for building customized, time-delayed, distributed security events.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/redcanaryco/atomic-red-team">redcanaryco/atomic-red-team</a></td>
        <td>Small and highly portable detection tests based on MITRE's ATT&CK.</td>
    </tr>
	<tr>
		<td><a href="https://github.com/redcanaryco/chain-reactor">redcanaryco/chain-reactor</a></td>
		<td>Chain Reactor is an open source framework for composing executables that simulate adversary behaviors and techniques on Linux endpoints.</td>
	</tr>
    <tr>
        <td><a href="https://github.com/redhuntlabs/RedHunt-OS">redhuntlabs/RedHunt-OS</a></td>
        <td>Virtual Machine for Adversary Emulation and Threat Hunting</td>
    </tr>
    <tr>
        <td><a href="https://github.com/SpiderLabs/sheepl">SpiderLabs/sheepl</a></td>
        <td>Sheepl : Creating realistic user behaviour for supporting tradecraft development within lab environments</td>
    </tr>
	<tr>
		<td><a href="https://github.com/splunk/attack_range">splunk/attack_range</a></td>
		<td>A tool that allows you to create vulnerable instrumented local or cloud environments to simulate attacks against and collect the data into Splunk</td>
	</tr>
    <tr>
        <td><a href="https://github.com/swimlane/soc-faker">swimlane/soc-faker</a></td>
        <td>A python package for use in generating fake data for SOC and security automation.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/uber-common/metta">uber-common/metta</a></td>
        <td>An information security preparedness tool to do adversarial simulation.</td>
    </tr>
    <tr>
        <td><a href="https://mitre.github.io/unfetter/">Unfetter</a></td>
        <td>Unfetter is a project designed to help network defenders, cyber security professionals, and decision makers identify and analyze defensive gaps in a more scalable and repeatable way</td>
    </tr>
</table>

## Application Security

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/aboul3la/Sublist3r">aboul3la/Sublist3r</a></td>
        <td>Fast subdomains enumeration tool for penetration testers</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Acheron-VAF/Acheron">Acheron-VAF/Acheron</a></td>
        <td>Acheron is a RESTful vulnerability assessment and management framework built around search and dedicated to terminal extensibility.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ambionics/phpggc">ambionics/phpggc</a></td>
        <td>PHPGGC is a library of unserialize() payloads along with a tool to generate them, from command line or programmatically.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/anchore/grype">anchore/grype</a></td>
        <td>A vulnerability scanner for container images and filesystems</td>
    </tr>
    <tr>
        <td><a href="https://github.com/appsecco/spaces-finder">appsecco/spaces-finder</a></td>
        <td>A tool to hunt for publicly accessible DigitalOcean Spaces</td>
    </tr>
    <tr>
        <td><a href="https://github.com/anantshri/svn-extractor">anatshri/svn-extractor</a></td>
        <td>Simple script to extract all web resources by means of .SVN folder exposed over network.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/brannondorsey/dns-rebind-toolkit">brannondorsey/dns-rebind-toolkit</a></td>
        <td>A front-end JavaScript toolkit for creating DNS rebinding attacks.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/BishopFox/h2csmuggler">BishopFox/h2csmuggler</a></td>
        <td>HTTP Request Smuggling over HTTP/2 Cleartext (h2c)</td>
    </tr>
    <tr>
        <td><a href="https://github.com/danmar/cppcheck">danmar/cppcheck</a></td>
        <td>static analysis of C/C++ code</td>
    </tr>
    <tr>
        <td><a href="https://github.com/dstotijn/hetty">dstotijn/hetty</a></td>
        <td>Hetty is an HTTP toolkit for security research. It aims to become an open source alternative to commercial software like Burp Suite Pro, with powerful features tailored to the needs of the infosec and bug bounty community.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/facebook/pyre-check/">facebook/pyre-check/</a></td>
        <td>Performant type-checking for python.</td>
    </tr>
    <tr>
        <td><a href="https://huntersuite.io/">HunterSuite</a></td>
        <td>HunterSuite is the next generation offensive security suite. It will automate all the tedious tasks during a test just with few clicks. If you are a penetration tester, red teamer, bug bounty hunter, or you work as an offensive security engineer, you will love what HunterSuite has to offer.</td>
    </tr>
    <tr>
        <td><a href="https://illuminatejs.geeksonsecurity.com/">IlluminateJs</a></td>
        <td>IlluminateJs is a static javascript analysis engine (a deobfuscator so to say) aimed to help analyst understand obfuscated and potentially malicious JavaScript Code.</td>
    </tr>
    </tr>
    <tr>
        <td><a href="https://github.com/ismailtasdelen/xss-payload-list">ismailtasdelen/xss-payload-list</a></td>
        <td>Cross Site Scripting ( XSS ) Vulnerability Payload List</td>
    </tr>
    <tr>
        <td><a href="https://github.com/jonluca/Anubis">jonluca/Anubis</a></td>
        <td>Subdomain enumeration and information gathering tool</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mazen160/bfac">mazen160/bfac</a></td>
        <td>BFAC (Backup File Artifacts Checker): An automated tool that checks for backup artifacts that may disclose the web-application's source code.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/microsoft/onefuzz">microsoft/onefuzz</a></td>
        <td>A self-hosted Fuzzing-As-A-Service platform</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mindedsecurity/JStillery">mindedsecurity/JStillery</a></td>
        <td>Advanced JS Deobfuscation via Partial Evaluation.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mwrlabs/dref">mwrlabs/dref</a></td>
        <td>DNS Rebinding Exploitation Framework</td>
    </tr>
    <tr>
	<td><a href="https://github.com/nccgroup/whalescan">nccgroup/whalescan</a></td>
	<td>Whalescan is a vulnerability scanner for Windows containers, which performs several benchmark checks, as well as checking for CVEs/vulnerable packages on the container</td>
    </tr>
    <tr>
        <td><a href="https://github.com/NetSPI/AutoDirbuster">NetSPI/AutoDirbuster</a></td>
        <td>Automatically run and save Dirbuster scans for multiple IPs</td>
    </tr>
    <tr>
        <td><a href="https://github.com/NetSPI/PowerUpSQL">NetSPI/PowerUpSQL</a></td>
        <td>PowerUpSQL: A PowerShell Toolkit for Attacking SQL Server</td>
    </tr>
    <tr>
        <td><a href="https://github.com/nccgroup/singularity">nccgroup/singularity</a></td>
        <td>A DNS rebinding attack framework</td>
    </tr>
    <tr>
        <td><a href="https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project">OWASP Zed Attack Proxy Project</a></td>
        <td>The OWASP Zed Attack Proxy (ZAP) is one of the world’s most popular free security tools and is actively maintained by hundreds of international volunteers*. It can help you automatically find security vulnerabilities in your web applications while you are developing and testing your applications. Its also a great tool for experienced pentesters to use for manual security testing</td>
    </tr>
    <tr>
        <td><a href="https://publicwww.com/">Public WWW</a></td>
        <td>Source Code Search Engine</td>
    </tr>
    <tr>
        <td><a href="https://github.com/pumasecurity/puma-scan">pumasecurity/puma-scan</a></td>
        <td>Puma Scan is a software security Visual Studio extension that provides real time, continuous source code analysis as development teams write code. Vulnerabilities are immediately displayed in the development environment as spell check and compiler warnings, preventing security bugs from entering your applications.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/pwntester/ysoserial.net">pwntester/ysoserial.net</a></td>
        <td>Deserialization payload generator for a variety of .NET formatters</td>
    </tr>
    <tr>
        <td><a href="https://github.com/RhinoSecurityLabs/IPRotate_Burp_Extension">RhinoSecurityLabs/IPRotate_Burp_Extension</a></td>
        <td>Extension for Burp Suite which uses AWS API Gateway to rotate your IP on every request.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/RhinoSecurityLabs/SleuthQL">RhinoSecurityLabs/SleuthQL</a></td>
        <td>Python3 Burp History parsing tool to discover potential SQL injection points. To be used in tandem with SQLmap.</td>
    </tr>
    <tr>
        <td><a href="https://snyk.io/">Snyk</a></td>
        <td>Continuously find & fix vulnerabilities in your dependencies</td>
    </tr>
    <tr>
        <td><a href="https://github.com/s0md3v/XSStrike">s0md3v/XSStrike</a></td>
        <td>Most advanced XSS detection suite</td>
    </tr>
    <tr>
        <td><a href="https://github.com/subfinder/subfinder">subfinder/subfinder</a></td>
        <td>SubFinder is a subdomain discovery tool that discovers valid subdomains for websites. Designed as a passive framework to be useful for bug bounties and safe for penetration testing.</td>
    </tr>
	<tr>
		<td><a href="https://github.com/Yelp/detect-secrets">Yelp/detect-secrets</a></td>
		<td>An enterprise friendly way of detecting and preventing secrets in code.</td>
	</tr>
</table>

## Binary Analysis

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/avast-tl/retdec">avast-tl/retdec</a></td>
        <td>RetDec is a retargetable machine-code decompiler based on LLVM</td>
    </tr>
    <tr>
        <td><a href="https://binvis.io/#/">binvis.io</a></td>
        <td>visual analysis of binary files</td>
    </tr>
    <tr>
        <td><a href="https://github.com/blackberry/pe_tree">blackberry/pe_tree</a></td>
        <td>Python module for viewing Portable Executable (PE) files in a tree-view using pefile and PyQt5. Can also be used with IDA Pro to dump in-memory PE files and reconstruct imports.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/carbonblack/binee">carbonblack/binee</a></td>
        <td>Binee: binary emulation environment</td>
    </tr>
    <tr>
        <td><a href="https://github.com/bootleg/ret-sync">bootleg/ret-sync</a></td>
        <td>ret-sync is a set of plugins that helps to synchronize a debugging session (WinDbg/GDB/LLDB/OllyDbg2/x64dbg) with IDA/Ghidra disassemblers.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Cisco-Talos/GhIDA">Cisco-Talos/GhIDA</a></td>
        <td>GhIDA is an IDA Pro plugin that integrates the Ghidra decompiler in IDA.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Cisco-Talos/Ghidraaas">Cisco-Talos/Ghidraaas</a></td>
        <td>Ghidraaas is a simple web server that exposes Ghidra analysis through REST APIs. The project includes three Ghidra plugins to analyze a sample, get the list of functions and to decompile a function.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Comsecuris/gdbghidra">Comsecuris/gdbghidra</a></td>
        <td>gdbghidra - a visual bridge between a GDB session and GHIDRA</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Comsecuris/gdbida">Comsecuris/gdbida</a></td>
        <td>gdbida - a visual bridge between a GDB session and IDA Pro's disassembler</td>
    </tr>
    <tr>
        <td><a href="https://cutter.re/">Cutter</a></td>
        <td>Free and Open Source RE Platform powered by radare2</td>
    </tr>
    <tr>
        <td><a href="https://github.com/DarthTon/Blackbone">DarthTon/Blackbone</a></td>
        <td>Windows memory hacking library</td>
    </tr>
    <tr>
        <td><a href="https://github.com/endgameinc/xori">endgameinc/xori</a></td>
        <td>Xori is an automation-ready disassembly and static analysis library for PE32, 32+ and shellcode</td>
    </tr>
    <tr>
        <td><a href="https://github.com/enkomio/shed">enkomio/shed</a></td>
        <td>.NET runtine inspector. <a href="http://antonioparata.blogspot.it/2017/11/shed-inspect-net-malware-like-sir.html">Shed - Inspect .NET malware like a Sir</a></td>
    </tr>
    <tr>
        <td><a href="https://github.com/fireeye/flare-floss">fireeye/flare-floss</a></td>
        <td>FireEye Labs Obfuscated String Solver - Automatically extract obfuscated strings from malware.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/fireeye/speakeasy">fireeye/speakeasy</a></td>
        <td>Speakeasy is a portable, modular, binary emulator designed to emulate Windows kernel and user mode malware.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/FuzzySecurity/Fermion">FuzzySecurity/Fermion</a></td>
        <td>Fermion, an electron wrapper for Frida & Monaco.</td>
    </tr>
    <tr>
        <td><a href="https://ghidra-sre.org/">GHIDRA</a></td>
        <td>A software reverse engineering (SRE) suite of tools developed by NSA's Research Directorate in support of the Cybersecurity mission</td>
    </tr>
    <tr>
        <td><a href="https://go-re.tk/">Go Reverse Engineering Toolkit</a></td>
        <td>A Reverse Engineering Tool Kit for Go, Written in Go.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/hasherezade/hollows_hunter">hasherezade/hollows_hunter</a></td>
        <td>A process scanner detecting and dumping hollowed PE modules.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/hasherezade/hook_finder">hasherezade/hook_finder</a></td>
        <td>a small tool for investigating inline hooks (and other in-memory code patches)</td>
    </tr>
    <tr>
        <td><a href="https://lief.quarkslab.com/">LIEF</a></td>
        <td>Library to Instrument Executable Formats</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Microsoft/binskim">Microsoft/binskim</a></td>
        <td>A binary static analysis tool that provides security and correctness results for Windows portable executables</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Microsoft/ProcDump-for-Linux">Microsoft/ProcDump-for-Linux</a></td>
        <td>A Linux version of the ProcDump Sysinternals tool</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mxmssh/drltrace">mxmssh/drltrace</a></td>
        <td>Drltrace is a library calls tracer for Windows and Linux applications</td>
    </tr>
    <tr>
        <td><a href="https://github.com/NASA-SW-VnV/ikos">NASA-SW-VnV/ikos</a></td>
        <td>IKOS (Inference Kernel for Open Static Analyzers) is a static analyzer for C/C++ based on the theory of Abstract Interpretation</td>
    </tr>
    <tr>
        <td><a href="https://github.com/nccgroup/WindowsMemPageDelta">nccgroup/WindowsMemPageDelta</a></td>
        <td>A Microsoft Windows service to provide telemetry on Windows executable memory page changes to facilitate threat detection</td>
    </tr>
    <tr>
        <td><a href="https://github.com/pierrezurek/Signsrch">pierrezurek/Signsrch</a></td>
        <td>tool for searching signatures inside files, extremely useful in reversing engineering for figuring or having an initial idea of what encryption/compression algorithm is used for a proprietary protocol or file. it can recognize tons of compression, multimedia and encryption algorithms and many other things like known strings and anti-debugging code which can be also manually added since it's all based on a text signature file read at runtime and easy to modify.</td>
    </tr>
    <tr>
        <td><a href="https://rayanfam.com/topics/pinitor/">Pinitor</a></td>
        <td>An API Monitor Based on Pin</td>
    </tr>
    <tr>
        <td><a href="https://pypi.org/project/pygore/">pygore</a></td>
        <td>Python library for analyzing Go binaries</td>
    </tr>
    <tr>
        <td><a href="https://github.com/qilingframework/qiling">qilingframework/qiling</a></td>
        <td>Qiling Advanced Binary Emulation Framework</td>
    </tr>
    <tr>
        <td><a href="https://github.com/taviso/loadlibrary">taviso/loadlibrary</a></td>
        <td>Porting Windows Dynamic Link Libraries to Linux</td>
    </tr>
    <tr>
        <td><a href="https://github.com/secretsquirrel/recomposer">secretsquirrel/recomposer</a></td>
        <td>Randomly changes Win32/64 PE Files for 'safer' uploading to malware and sandbox sites.</td>
    </tr>
    <tr>
        <td><a href="https://shellcode.run/">shellcode.run</a></td>
        <td>A sandbox, for shellcode - run your shellcode blobs online with no hassle and receive a comprehensive report.</td>
    </tr>
    <tr>
        <td><a href="https://codisec.com/veles/">Veles</a></td>
        <td>New open source tool for binary data analysis</td>
    </tr>
    <tr>
        <td><a href="https://salmanarif.bitbucket.io/visual/index.html">VisUAL</a></td>
        <td>A highly visual ARM emulator</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Wenzel/checksec.py">Wenzel/checksec.py</a></td>
        <td>Checksec tool in Python, Rich output. Based on LIEF</td>
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

## Cloud Security

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/0xsha/CloudBrute/">0xsha/CloudBrute</a></td>
        <td>A tool to find a company (target) infrastructure, files, and apps on the top cloud providers (Amazon, Google, Microsoft, DigitalOcean, Alibaba, Vultr, Linode). The outcome is useful for bug bounty hunters, red teamers, and penetration testers alike.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Alfresco/prowler">Alfresco/prowler</a></td>
        <td>Tool for AWS security assessment, auditing and hardening. It follows guidelines of the CIS Amazon Web Services Foundations Benchmark.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/andresriancho/nimbostratus">andresriancho/nimbostratus</a></td>
        <td>Tools for fingerprinting and exploiting Amazon cloud infrastructures</td>
    </tr>
	<tr>
		<td><a href="https://asecure.cloud/">asecure.cloud</a></td>
		<td>A free repository of customizable AWS security configurations and best practices</td>
	</tr>
    <tr>
        <td><a href="https://bitbucket.org/asecurityteam/spacecrab">asecurityteam/spacecrab</a></td>
        <td>Bootstraps an AWS account with everything you need to generate, mangage, and distribute and alert on AWS honey tokens. Made with breakfast roti by the Atlassian security team.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/awslabs/aws-security-benchmark">awslabs/aws-security-benchmark</a></td>
        <td>Open source demos, concept and guidance related to the AWS CIS Foundation framework.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Azure/Stormspotter">Azure/Stormspotter</a></td>
        <td>Azure Red Team tool for graphing Azure and Azure Active Directory objects</td>
    </tr>
	<tr>
		<td><a href="https://github.com/bridgecrewio/cdkgoat">bridgecrewio/cdkgoat</a></td>
		<td>CdkGoat is Bridgecrew's "Vulnerable by Design" AWS CDK repository. CdkGoat is a learning and training project that demonstrates how common configuration errors can find their way into production cloud environments.</td>
	</tr>
	<tr>
		<td><a href="https://github.com/bridgecrewio/cfngoat">bridgecrewio/cfngoat</a></td>
		<td>Cfngoat is Bridgecrew's "Vulnerable by Design" Cloudformation repository. Cfngoat is a learning and training project that demonstrates how common configuration errors can find their way into production cloud environments.</td>
	</tr>
    <tr>
        <td><a href="https://github.com/carnal0wnage/weirdAAL/wiki">carnal0wnage/weirdAAL</a></td>
        <td>WeirdAAL [AWS Attack Library] wiki!</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cloudsploit/scans">cloudsploit/scans</a></td>
        <td>AWS security scanning checks</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cr0hn/festin">cr0hn/festin</a></td>
        <td>FestIn is a tool for discovering open S3 Buckets starting from a domains.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cyberark/SkyArk">cyberark/SkyArk</a></td>
        <td>SkyArk is a cloud security tool, helps to discover, assess and secure the most privileged entities in AWS</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cyberark/SkyWrapper">cyberark/SkyWrapper</a></td>
        <td>SkyWrapper helps to discover suspicious creation forms and uses of temporary tokens in AWS</td>
    </tr>
    <tr>
        <td><a href="https://github.com/dagrz/aws_pwn">dagrz/aws_pwn</a></td>
        <td>A collection of AWS penetration testing junk</td>
    </tr>
    <tr>
        <td><a href="https://github.com/disruptops/cred_scanner">disruptops/cred_scanner</a></td>
        <td>A simple file-based scaner to look for potential AWS accesses and secret keys in files</td>
    </tr>
    <tr>
        <td><a href="https://github.com/duo-labs/cloudtracker">duo-labs/cloudtracker</a></td>
        <td>CloudTracker helps you find over-privileged IAM users and roles by comparing CloudTrail logs with current IAM policies.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/duo-labs/cloudmapper">duo-labs/cloudmapper</a></td>
        <td>CloudMapper helps you analyze your Amazon Web Services (AWS) environments.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/endgameinc/varna">endgameinc/varna</a></td>
        <td>Varna: Quick & Cheap AWS CloudTrail Monitoring with Event Query Language (EQL)</td>
    </tr>
    <tr>
        <td><a href="https://github.com/eth0izzle/bucket-stream">eth0izzle/bucket-stream</a></td>
        <td>Find interesting Amazon S3 Buckets by watching certificate transparency logs.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/FishermansEnemy/bucket_finder">FishermansEnemy/bucket_finder</a></td>
        <td>Amazon bucket brute force tool</td>
    </tr>
    <tr>
        <td><a href="https://github.com/glen-mac/goGetBucket">glen-mac/goGetBucket</a></td>
        <td>A penetration testing tool to enumerate and analyse Amazon S3 Buckets owned by a domain.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/google/cloud-forensics-utils">google/cloud-forensics-utils</a></td>
        <td>Python library to carry out DFIR analysis on the Cloud</td>
    </tr>
    <tr>
        <td><a href="https://github.com/hausec/PowerZure">hausec/PowerZure</a></td>
        <td>PowerShell framework to assess Azure security</td>
    </tr>
    <tr>
        <td><a href="https://github.com/kromtech/s3-inspector">kromtech/s3-inspector</a></td>
        <td>Tool to check AWS S3 bucket permissions</td>
    </tr>
    <tr>
        <td><a href="https://github.com/jordanpotti/AWSBucketDump">jordanpotti/AWSBucketDump</a></td>
        <td>Security Tool to Look For Interesting Files in S3 Buckets</td>
    </tr>
    <tr>
        <td><a href="https://github.com/jordanpotti/CloudScraper">jordanpotti/CloudScraper</a></td>
        <td>CloudScraper: Tool to enumerate targets in search of cloud resources. S3 Buckets, Azure Blobs, Digital Ocean Storage Space.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/lyft/metadataproxy">lyft/metadataproxy</a></td>
        <td>A proxy for AWS's metadata service that gives out scoped IAM credentials from STS</td>
    </tr>
    <tr>
        <td><a href="https://github.com/MindPointGroup/cloudfrunt">MindPointGroup/cloudfrunt</a></td>
        <td>A tool for identifying misconfigured CloudFront domains</td>
    </tr>
    <tr>
        <td><a href="https://github.com/nccgroup/aws-inventory">nccgroup/aws-inventory</a></td>
        <td>Discover resources created in an AWS account</td>
    </tr>
    <tr>
        <td><a href="https://github.com/nccgroup/PMapper">nccgroup/PMapper</a></td>
        <td>A tool for quickly evaluating IAM permissions in AWS.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/nccgroup/Scout2">nccgroup/Scout2</a></td>
        <td>Security auditing tool for AWS environments</td>
    </tr>
    <tr>
        <td><a href="https://github.com/nccgroup/ScoutSuite">nccgroup/ScoutSuite</a></td>
        <td>Scout Suite is an open source multi-cloud security-auditing tool, which enables security posture assessment of cloud environments</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Netflix-Skunkworks/diffy">Netflix-Skunkworks/diffy</a></td>
        <td>Diffy is a digital forensics and incident response (DFIR) tool developed by Netflix's Security Intelligence and Response Team (SIRT).</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Netflix/security_monkey">Netflix/security_monkey</a></td>
        <td>Security Monkey monitors your AWS and GCP accounts for policy changes and alerts on insecure configurations.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/NetSPI/aws_consoler">NetSPI/aws_consoler</a></td>
        <td>A utility to convert your AWS CLI credentials into AWS console access.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/NotSoSecure/cloud-service-enum/">NotSoSecure/cloud-service-enum</a></td>
        <td>This script allows pentesters to validate which cloud tokens (API keys, OAuth tokens and more) can access which cloud service.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/prevade/cloudjack">prevade/cloudjack</a></td>
        <td>Route53/CloudFront Vulnerability Assessment Utility</td>
    </tr>
    <tr>
        <td><a href="https://github.com/pumasecurity/serverless-prey">pumasecurity/serverless-prey</a></td>
        <td>Serverless Functions for establishing Reverse Shells to Lambda, Azure Functions, and Google Cloud Functions</td>
    </tr>
    <tr>
        <td><a href="https://github.com/random-robbie/slurp">random-robbie/slurp</a></td>
        <td>Enumerate S3 buckets via certstream, domain, or keywords</td>
    </tr>
    <tr>
        <td><a href="https://github.com/RhinoSecurityLabs/pacu">RhinoSecurityLabs/pacu</a></td>
        <td>Rhino Security Labs' AWS penetration testing toolkit</td>
    </tr>
    <tr>
        <td><a href="https://github.com/RiotGames/cloud-inquisitor">RiotGames/cloud-inquisitor</a></td>
        <td>Enforce ownership and data security within AWS</td>
    </tr>
    <tr>
        <td><a href="https://github.com/sa7mon/S3Scanner">sa7mon/S3Scanner</a></td>
        <td>Scan for open S3 buckets and dump</td>
    </tr>
    <tr>
        <td><a href="https://github.com/salesforce/cloudsplaining">salesforce/cloudsplaining</a></td>
        <td>Cloudsplaining is an AWS IAM Security Assessment tool that identifies violations of least privilege and generates a risk-prioritized HTML report with a triage worksheet</td>
    </tr>
    <tr>
        <td><a href="https://github.com/sendgrid/krampus">sendgrid/krampus</a></td>
        <td>The original AWS security enforcer™</td>
    </tr>
    <tr>
        <td><a href="https://github.com/SecurityFTW/cs-suite">SecurityFTW/cs-suite</a></td>
        <td>Cloud Security Suite - One stop tool for auditing the security posture of AWS infrastructure.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/spacesiren/spacesiren">spacesiren/spacesiren</a></td>
        <td>A honey token manager and alert system for AWS.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/swimlane/CLAW">swimlane/CLAW</a></td>
        <td>A packer utility to create and capture DFIR Image for use AWS & Azure</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ThreatResponse/margaritashotgun">ThreatResponse/margaritashotgun</a></td>
        <td>Remote Memory Acquisition Tool for AWS</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ThreatResponse/aws_ir">ThreatResponse/aws_ir</a></td>
        <td>Python installable command line utiltity for mitigation of host and key compromises.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/toniblyx/prowler">toniblyx/prowler</a></td>
        <td>Tool based on AWS-CLI commands for AWS account security assessment and hardening, following guidelines of the CIS Amazon Web Services Foundations Benchmark 1.1</td>
    </tr>
    <tr>
        <td><a href="https://github.com/widdix/aws-s3-virusscan">widdix/aws-s3-virusscan</a></td>
        <td>Antivirus for Amazon S3 buckets</td>
    </tr>
</table>

## Courses

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/specterops/at-ps">specterops/at-ps</a></td>
        <td>Adversary Tactics - PowerShell Training</td>
    </tr>
</table>

## Cryptography

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/CERTCC/keyfinder">CERTCC/keyfinder</a></td>
        <td>A tool for analyzing private (and public) key files, including support for Android APK files.</td>
    </tr>
    <tr>
        <td><a href="https://certdb.com">CertDB</a></td>
        <td>Internet-wide search engine for digital certificates</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Ciphey/Ciphey">Ciphey/Ciphey</a></td>
        <td>Automatically decode encryptions without a key, decode encodings, and crack hashes</td>
    </tr>
    <tr>
        <td><a href="https://github.com/corkami/pocs/">corkami/pocs</a></td>
        <td>Proof of Concepts (PE, PDF...)</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mpgn/BEAST-PoC">mpgn/BEAST-PoC</a></td>
        <td>Poc of BEAST attack against SSL/TLS</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mpgn/Padding-oracle-attack">mpgn/Padding-oracle-attack</a></td>
        <td>Padding oracle attack against PKCS7</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mpgn/poodle-PoC">mpgn/poodle-PoC</a></td>
        <td>Poodle (Padding Oracle On Downgraded Legacy Encryption) attack</td>
    </tr>
    <tr>
        <td><a href="https://github.com/salesforce/ja3">salesforce/ja3</td>
        <td>JA3 is a standard for creating SSL client fingerprints in an easy to produce and shareable way.</td>
    </tr>
</table>

## Data Exfiltration

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
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
    <tr>
        <td><a href="https://github.com/SySS-Research/Seth">SySS-Research/Seth</a></td>
        <td>Perform a MitM attack and extract clear text credentials from RDP connections</td>
    </tr>
</table>

## Data Sets

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
    <tr>
        <td><a href="https://www.splunk.com/blog/2018/05/10/boss-of-the-soc-scoring-server-questions-and-answers-and-dataset-open-sourced-and-ready-for-download.html">BOTS 1.0 Dataset</a></td>
        <td>The BOTS 1.0 dataset records two attacks perpetrated by a fictitious hacktivist group called po1s0n1vy targeting Wayne Corp of Batman mythology. There are many comic book references in the data; from heroes and villains to “Batman’s” street addresses. Not only does the dataset have many different types of data—everything from Sysmon to Suricata—but there are even file hashes that can be found in Virustotal.com and domains/IPs to hunt for in OSINT tools like PassiveTotal and Robtex!</td>
    </tr>
    <tr>
        <td><a href="https://toolbox.google.com/datasetsearch">Google Dataset Search</a></td>
        <td>Google Dataset Search</td>
    </tr>
    <tr>
        <td><a href="http://www.secrepo.com/">SecRepo.com - Samples of Security Related Data</a></td>
        <td>Finding samples of various types of Security related can be a giant pain. This is my attempt to keep a somewhat curated list of Security related data I've found, created, or was pointed to. If you perform any kind of analysis with any of this data please let me know and I'd be happy to link it from here or host it here. Hopefully by looking at others research and analysis it will inspire people to add-on, improve, and create new ideas.</td>
    </tr>
</table>

## Digital Forensics and Incident Response

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
    <tr>
        <td><a href="https://www.flashbackdata.com/free-forensics-tool-i-file-parser/">$I File Parser</a></td>
        <td>Free Forensics Tool – \$I File Parser</td>
    </tr>
    <tr>
        <td><a href="https://github.com/activecm/BeaKer">activecm/BeaKer</a></td>
        <td>Beacon Kibana Executable Report. Aggregates Sysmon Network Events With Elasticsearch and Kibana</td>
    </tr>
    <tr>
        <td><a href="https://www.alienvault.com/products/ossim">AlienVault OSSIM</a></td>
        <td>AlienVault OSSIM: The World’s Most Widely Used Open Source SIEM</td>
    </tr>
    <tr>
		<td><a href="https://github.com/andreafortuna/autotimeliner">andreafortuna/autotimeliner</a></td>
		<td>Automagically extract forensic timeline from volatile memory dump</td>
	</tr>
    <tr>
        <td><a href="https://github.com/ANSSI-FR/bits_parser">ANSSI-FR/bits_parser</a></td>
        <td>Extract BITS jobs from QMGR queue and store them as CSV records</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ANSSI-FR/bmc-tools">ANSSI-FR/bmc-tools</a></td>
        <td>RDP Bitmap Cache Parser</td>
    </tr>
    <tr>
        <td><a href="https://github.com/bfuzzy/auditd-attack">bfuzzy/auditd-attack</a></td>
        <td>A Linux Auditd rule set mapped to MITRE's Attack Framework</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Broctets-and-Bytes/Darwin">Broctets-and-Bytes/Darwin</a></td>
        <td>This script is designed to be run against a mounted image, live system, or device in target disk mode. The script automates the collection of key files for MacOS investigations.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/bromiley/olaf">bromiley/olaf</a></td>
        <td>Office365 Log Analysis Framework: OLAF is a collection of tools, scripts, and analysis techniques dealing with O365 Investigations.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/carmaa/inception">carmaa/inception</a></td>
        <td>Inception is a physical memory manipulation and hacking tool exploiting PCI-based DMA. The tool can attack over FireWire, Thunderbolt, ExpressCard, PC Card and any other PCI/PCIe interfaces.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/coinbase/dexter">coinbase/dexter</a></td>
        <td>Forensics acquisition framework designed to be extensible and secure</td>
    </tr>
    <tr>
        <td><a href="https://github.com/CrowdStrike/automactc">CrowdStrike/automactc</a></td>
        <td>AutoMacTC: Automated Mac Forensic Triage Collector</td>
    </tr>
    <tr>
        <td><a href="https://github.com/CrowdStrike/Forensics">CrowdStrike/Forensics</a></td>
        <td>Scripts and code referenced in CrowdStrike blog posts</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cryps1s/DARKSURGEON">cryps1s/DARKSURGEON</a></td>
        <td>DARKSURGEON is a Windows packer project to empower incident response, digital forensics, malware analysis, and network defense.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cyb3rfox/Aurora-Incident-Response">cyb3rfox/Aurora-Incident-Response</a></td>
        <td>Incident Response Documentation made easy. Developed by Incident Responders for Incident Responders</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Cyb3rWard0g/HELK">Cyb3rWard0g/HELK</a></td>
        <td>A Hunting ELK (Elasticsearch, Logstash, Kibana) with advanced analytic capabilities.</td>
    </tr>
    <tr>
        <td><a href="https://car.mitre.org/">Cyber Analytics Repository</a></td>
        <td>The MITRE Cyber Analytics Repository (CAR) is a knowledge base of analytics developed by MITRE based on the MITRE ATT&CK adversary model.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/CyberDefenseInstitute/CDIR">CyberDefenseInstitute/CDIR</a></td>
        <td>CDIR (Cyber Defense Institute Incident Response) Collector - live collection tool based on oss tool/library</td>
    </tr>
    <tr>
        <td><a href="https://github.com/davehull/Kansa">davehull/Kansa</a></td>
        <td>A Powershell incident response framework</td>
    </tr>
    <tr>
        <td><a href="https://dfir-orc.github.io/">DFIR ORC</a></td>
        <td>DFIR ORC, where ORC stands for “Outil de Recherche de Compromission” in French, is a collection of specialized tools dedicated to reliably parse and collect critical artefacts such as the MFT, registry hives or event logs. It can also embed external tools and their configurations.</td>
    </tr>
    <tr>
        <td><a href="https://info.digitalguardian.com/wingman.html">DG Wingman</a></td>
        <td>DG Wingman is a free community Windows tool designed to aid in the collection of forensic evidence in order to properly investigate and scope an intrusion.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/draios/sysdig">draios/sysdig</a></td>
        <td>Linux system exploration and troubleshooting tool with first class support for containers</td>
    </tr>
    <tr>
        <td><a href="https://github.com/drego85/meioc">drego85/meioc</a></td>
        <td>Extracting IoC data from eMail</td>
    </tr>
    <tr>
        <td><a href="https://github.com/DFIRKuiper/Kuiper">DFIRKuiper/Kuiper</a></td>
        <td>Kuiper is a digital investigation platform that provides a capabilities for the investigation team and individuals to parse, search, visualize collected evidences (evidences could be collected by fast traige script like Hoarder).</td>
    </tr>
    <tr>
        <td><a href="https://github.com/fireeye/ARDvark">fireeye/ARDvark</a></td>
        <td>ARDvark parses the Apple Remote Desktop (ARD) files to pull out application usage, user activity, and filesystem listings.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/fireeye/SilkETW">fireeye/SilkETW</a></td>
        <td>SilkETW & SilkService are flexible C# wrappers for ETW, they are meant to abstract away the complexities of ETW and give people a simple interface to perform research and introspection.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ForensicArtifacts/artifacts">ForensicArtifacts/artifacts</a></td>
        <td>Digital Forensics Artifact Repository</td>
    </tr>
    <tr>
        <td><a href="https://github.com/gleeda/memtriage">gleeda/memtriage</a></td>
        <td>Allows you to quickly query a Windows machine for RAM artifacts</td>
    </tr>
    <tr>
        <td><a href="https://github.com/google/docker-explorer/">google/docker-explorer</a></td>
        <td>A tool to help forensicate offline docker acquisitions</td>
    </tr>
    <tr>
        <td><a href="https://github.com/google/GiftStick">google/GiftStick</a></td>
        <td>1-Click push forensics evidence to the cloud</td>
    </tr>
    <tr>
        <td><a href="https://github.com/google/grr">google/grr</a></td>
        <td>GRR is a python client (agent) that is installed on target systems, and python server infrastructure that can manage and talk to clients.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/google/rekall">google/rekall</a></td>
        <td>The Rekall Framework is a completely open collection of tools, implemented in Python under the Apache and GNU General Public License, for the extraction and analysis of digital artifacts computer systems.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/google/turbinia">google/turbinia</a></td>
        <td>Automation and Scaling of Digital Forensics Tools</td>
    </tr>
    <tr>
        <td><a href="https://www.graylog.org/">Graylog</a></td>
        <td>Built to open standards, Graylog’s connectivity and interoperability seamlessly collects, enhances, stores, and analyzes log data.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/hunters-forge/api-to-event">hunters-forge/API-To-Event</a></td>
        <td>A repo to document API functions mapped to security events across diverse platforms</td>
    </tr>
    <tr>
        <td><a href="https://github.com/hunters-forge/OSSEM">hunters-forge/OSSEM</a></td>
        <td>Open Source Security Events Metadata (OSSEM)</td>
    </tr>
    <tr>
        <td><a href="https://securelist.com/happy-ir-in-the-new-year/83557/">Kaspersky IR's Artifacts Collector</a></td>
        <td>Kaspersky IR's Artifacts Collector</td>
    </tr>
    <tr>
        <td><a href="https://arsenalrecon.com/downloads/">Hibernation Recon</a></td>
        <td>The tools and techniques used for many years to analyze Microsoft Windows® hibernation files have left digital forensics experts in the dark… until now!</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Invoke-IR/ACE">Invoke-IR/ACE</a></td>
        <td>The Automated Collection and Enrichment (ACE) platform is a suite of tools for threat hunters to collect data from many endpoints in a network and automatically enrich the data. The data is collected by running scripts on each computer without installing any software on the target. ACE supports collecting from Windows, macOS, and Linux hosts.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/jimtin/IRCoreForensicFramework">jimtin/IRCoreForensicFramework</a></td>
        <td>Powershell 7 (Powershell Core)/ C# cross platform forensic framework. Built by incident responders for incident responders.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/JPCERTCC/LogonTracer">JPCERTCC/LogonTracer</a></td>
        <td>Investigate malicious Windows logon by visualizing and analyzing Windows event log</td>
    </tr>
    <tr>
        <td><a href="https://github.com/JPCERTCC/SysmonSearch">JPCERTCC/SysmonSearch</a></td>
        <td>Investigate suspicious activity by visualizing Sysmon's event log</td>
    </tr>
    <tr>
        <td><a href="https://github.com/IllusiveNetworks-Labs/HistoricProcessTree">IllusiveNetworks-Labs/HistoricProcessTree</a></td>
        <td>An Incident Response tool that visualizes historic process execution evidence (based on Event ID 4688 - Process Creation Event) in a tree view.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/intezer/linux-explorer">intezer/linux-explorer</a></td>
        <td>Easy-to-use live forensics toolbox for Linux endpoints</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Invoke-IR/PowerForensics">Invoke-IR/PowerForensics</a></td>
        <td>PowerForensics provides an all in one platform for live disk forensic analysis</td>
    </tr>
    <tr>
        <td><a href="https://www.brimorlabsblog.com/2019/04/live-response-collection-cedarpelta.html">Live Response Collection - Cedarpelta</a></td>
        <td>Live Response Collection - Cedarpelta </td>
    </tr>
    <tr>
        <td><a href="https://github.com/log2timeline/plaso">log2timeline/plaso</a></td>
        <td>log2timeline is a tool designed to extract timestamps from various files found on a typical computer system(s) and aggregate them.</td>
    </tr>
	<tr>
		<td><a href="https://www.magnetforensics.com/resources/magnet-app-simulator/">MAGNET App Simulator</a></td>
		<td>MAGNET App Simulator lets you load application data from Android devices in your case into a virtual environment, enabling you to view and interact with the data as the user would have seen it on their own device.</td>
	</tr>
    <tr>
        <td><a href="https://github.com/MalwareSoup/MitreAttack">MalwareSoup/MitreAttack</a></td>
        <td>Python wrapper for the Mitre ATT&CK framework API</td>
    </tr>
    <tr>
        <td><a href="https://github.com/markbaggett/srum-dump">markbaggett/srum-dump</a></td>
        <td>A forensics tool to convert the data in the Windows srum (System Resource Usage Monitor) database to an xlsx spreadsheet.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/markbaggett/werejugo">markbaggett/werejugo</a></td>
        <td>Identifies physical locations where a laptop has been based upon wireless profiles and wireless data recorded in event logs</td>
    </tr>
    <tr>
        <td><a href="https://github.com/miriamxyra/EventList">miriamxyra/EventList</a></td>
        <td>EventList is a tool to help improving your Audit capabilities and to help to build your Security Operation Center.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mozilla/audit-go">mozilla/audit-go</a></td>
        <td>Linux Audit Plugin for heka written using netlink Protocol in golang and Lua</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mozilla/mig">mozilla/mig</a></td>
        <td>Distributed & real time digital forensics at the speed of the cloud</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mozilla/MozDef">mozilla/MozDef</a></td>
        <td>MozDef: The Mozilla Defense Platform</td>
    </tr>
    <tr>
        <td><a href="https://github.com/nannib/Imm2Virtual">nannib/Imm2Virtual</a></td>
        <td>This is a GUI (for Windows 64 bit) for a procedure to virtualize your EWF(E01), DD(Raw), AFF disk image file without converting it, directly with VirtualBox, forensically proof.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Netflix/dispatch">Netflix/dispatch</a></td>
        <td>All of the ad-hoc things you're doing to manage incidents today, done for you, and much more!</td>
    </tr>
    <tr>
        <td><a href="https://github.com/nshalabi/SysmonTools">nshalabi/SysmonTools</a></td>
        <td>Utilities for Sysmon (Sysmon View and Sysmon Shell)</td>
    </tr>
    <tr>
        <td><a href="https://nxlog.co/">NXLog</a></td>
        <td>The modern open source log collector.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/omenscan/achoir">omenscan/achoir</a></td>
        <td>Windows Live Artifacts Acquisition Script</td>
    </tr>
    <tr>
        <td><a href="https://github.com/orlikoski/CyLR">orlikoski/CyLR</a></td>
        <td>CyLR - Live Response Collection Tool</td>
    </tr>
    <tr>
        <td><a href="https://ossec.github.io/">OSSEC</a></td>
        <td>Open Source HIDS SECurity</td>
    </tr>
    <tr>
        <td><a href="https://github.com/philhagen/sof-elk">philhagen/sof-elk</a></td>
        <td>Configuration files for the SOF-ELK VM, used in SANS FOR572</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ptresearch/AttackDetection">ptresearch/AttackDetection</a></td>
        <td>The Attack Detection Team searches for new vulnerabilities and 0-days, reproduces it and creates PoC exploits to understand how these security flaws work and how related attacks can be detected on the network layer. Additionally, we are interested in malware and hackers’ TTPs, so we develop Suricata rules for detecting all sorts of such activities.</td>
    </tr>
	<tr>
		<td><a href="https://github.com/PUNCH-Cyber/stoq">PUNCH-Cyber/stoq</a></td>
		<td>An open source framework for enterprise level automated analysis.</td>
	</tr>
    <tr>
        <td><a href="https://rocknsm.io/">ROCK NSM</a></td>
        <td>Response Operation Collection Kit - An open source Network Security Monitoring platform.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/salesforce/bro-sysmon/">salesforce/bro-sysmon</td>
        <td>Bro-Sysmon enables Bro to receive Windows Event Logs. This provide a method to associate Network Monitoring and Host Monitoring. The work was spurred by the need to associate JA3 and HASSH fingerprints with the application on the host. The example below shows the hostname, Process ID, connection information, JA3 fingerprints, Application Path, and binary hashes.</td>
    </tr>
	<tr>
		<td><a href="https://github.com/sans-blue-team/DeepBlueCLI">sans-blue-team/DeepBlueCLI</a></td>
		<td>DeepBlueCLI - a PowerShell Module for Threat Hunting via Windows Event Logs</td>
	</tr>
    <tr>
        <td><a href="https://securityonion.net/">Security Onion</a></td>
        <td>Peel back the layers of your enterprise</td>
    </tr>
    <tr>
        <td><a href="https://github.com/SecurityRiskAdvisors/TALR">SecurityRiskAdvisors/TALR</a></td>
        <td>Threat Alert Logic Repository (TALR) - A public repository for the collection and sharing of detection rules in platform agnostic formats. Collected rules are appended with STIX required fields for simplified sharing over TAXII servers.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/SekoiaLab/fastir_artifacts">SekoiaLab/fastir_artifacts</a></td>
        <td>Live forensic artifacts collector</td>
    </tr>
    <tr>
        <td><a href="https://github.com/SekoiaLab/Fastir_Collector">SekoiaLab/Fastir_Collector</a></td>
        <td>This tool collects different artefacts on live Windows and records the results in csv or json files. With the analyses of these artefacts, an early compromission can be detected.</td>
    </tr>
    <tr>
        <td><a href="https://siemonster.com/">SIEMonster</a></td>
        <td>SIEMonster is an Affordable Security Monitoring Software Soulution</td>
    </tr>
    <tr>
        <td><a href="https://sigma.socprime.com/#!/">Sigma Rules Repository Mirror</a></td>
        <td>Sigma rules repository mirror and translations</td>
    </tr>
    <tr>
        <td><a href="https://github.com/slackhq/go-audit">slackhq/go-audit</a></td>
        <td>go-audit is an alternative to the auditd daemon that ships with many distros</td>
    </tr>
	<tr>
		<td><a href="https://github.com/s0md3v/Orbit">s0md3v/Orbit</a></td>
		<td>Blockchain Transactions Investigation Tool</td>
	</tr>
    <tr>
        <td><a href="https://github.com/refractionPOINT/limacharlie">refractionPOINT/limacharlie</a></td>
        <td>LC is an Open Source, cross-platform (Windows, MacOS, Linux ++), realtime Endpoint Detection and Response sensor. The extra-light sensor, once installed on a system provides Flight Data Recorder type information (telemetry on all aspects of the system like processes, DNS, network IO, file IO etc).</td>
    </tr>
    <tr>
        <td><a href="https://github.com/RomanEmelyanov/CobaltStrikeForensic">RomanEmelyanov/CobaltStrikeForensic</a></td>
        <td>Toolset for research malware and Cobalt Strike beacons</td>
    </tr>
    <tr>
        <td><a href="https://www.sleuthkit.org/">The Sleuth Kit</a></td>
        <td>sleuthkit.org is the official website for The Sleuth Kit®, Autopsy®, and other open source digital investigation tools. From here, you can find documents, case studies, and download the latest versions of the software.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/THIBER-ORG/userline">THIBER-ORG/userline</a></td>
        <td>Query and report user logons relations from MS Windows Security Events</td>
    </tr>
    <tr>
        <td><a href="https://github.com/trustedsec/SysmonCommunityGuide">trustedsec/SysmonCommunityGuide</a></td>
        <td>TrustedSec Sysinternals Sysmon Community Guide</td>
    </tr>
	<tr>
		<td><a href="https://github.com/ufrisk/LeechCore">ufrisk/LeechCore</a></td>
		<td>LeechCore - Physical Memory Acquisition Library & The LeechAgent Remote Memory Acquisition Agent</td>
	</tr>
    <tr>
        <td><a href="https://uncoder.io">Uncoder.io</a></td>
        <td>Uncoder.IO is the online translator for SIEM saved searches, filters, queries, API requests, correlation and Sigma rules to help SOC Analysts, Threat Hunters and SIEM Engineers</td>
    </tr>
    <tr>
        <td><a href="http://www.kazamiya.net/en/usn_analytics">USN Analytics</a></td>
        <td>USN Analytics is a tool that specializes in USN Journal ($UsnJrnl:$J) analysis</td>
    </tr>
    <tr>
        <td><a href="https://binaryforay.blogspot.com/2018/09/introducing-vscmount.html">VSCMount</a></td>
        <td>Volume shadow copies mounter tool</td>
    </tr>
    <tr>
        <td><a href="https://wazuh.com/">Wazuh</a></td>
        <td>Open Source Host and Endpoint Security</td>
    </tr>
    <tr>
        <td><a href="https://github.com/williballenthin/EVTXtract">williballenthin/EVTXtract</a></td>
        <td>EVTXtract recovers and reconstructs fragments of EVTX log files from raw binary data, including unallocated space and memory images.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/williballenthin/INDXParse">williballenthin/INDXParse</a></td>
        <td>Tool suite for inspecting NTFS artifacts</td>
    </tr>
    <tr>
        <td><a href="https://github.com/williballenthin/process-forest">williballenthin/process-forest</a></td>
        <td>process-forest is a tool that processes Microsoft Windows EVTX event logs that contain process accounting events and reconstructs the historical process heirarchies.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/yampelo/beagle">yampelo/beagle</a></td>
        <td>Beagle is an incident response and digital forensics tool which transforms security logs and data into graphs.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/zodiacon/ProcMonXv2">zodiacon/ProcMonXv2</a></td>
        <td>Procmon-like tool that uses Event Tracing for Windows (ETW) instead of a kernel driver to provide event information.</td>
    </tr>
</table>

## Exploits

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/externalist/exploit_playground">externalist/exploit_playground</a></td>
        <td>Analysis of public exploits or my 1day exploits</td>
    </tr>
    <tr>
        <td><a href="https://github.com/FriendsOfPHP/security-advisories">FriendsOfPHP/security-advisories</a></td>
        <td>The PHP Security Advisories Database references known security vulnerabilities in various PHP projects and libraries. This database must not serve as the primary source of information for security issues, it is not authoritative for any referenced software, but it allows to centralize information for convenience and easy consumption.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/gellin/TeamViewer_Permissions_Hook_V1">gellin/TeamViewer_Permissions_Hook_V1</a></td>
        <td>A proof of concept injectable C++ dll, that uses naked inline hooking and direct memory modification to change your TeamViewer permissions.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/HASecuritySolutions/VulnWhisperer">HASecuritySolutions/VulnWhisperer</a></td>
        <td>Create actionable data from your Vulnerability Scans</td>
    </tr>
    <tr>
        <td><a href="https://github.com/hasherezade/process_doppelganging">hasherezade/process_doppelganging</a></td>
        <td>My implementation of enSilo's Process Doppelganging (PE injection technique)</td>
    </tr>
    <tr>
        <td><a href="https://github.com/itm4n/UsoDllLoader">itm4n/UsoDllLoader</a></td>
        <td>Windows - Weaponizing privileged file writes with the Update Session Orchestrator service</td>
    </tr>
    <tr>
        <td><a href="https://github.com/jollheef/out-of-tree">jollheef/out-of-tree</a></td>
        <td>out-of-tree kernel {module, exploit} development tool</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ScottyBauer/Android_Kernel_CVE_POCs">ScottyBauer/Android_Kernel_CVE_POCs</a></td>
        <td>A list of my CVE's with POCs</td>
    </tr>
	<tr>
		<td><a href="https://github.com/smgorelik/Windows-RCE-exploits">smgorelik/Windows-RCE-exploits</a></td>
		<td>The exploit samples database is a repository for **RCE** (remote code execution) exploits and Proof-of-Concepts for **WINDOWS**, the samples are uploaded for education purposes for red and blue teams.</td>
	</tr>
    <tr>
        <td><a href="https://github.com/Spajed/processrefund">Spajed/processrefund</a></td>
        <td>An attempt at Process Doppelgänging</td>
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
        <td><a href="https://github.com/VulnReproduction/LinuxFlaw">VulnReproduction/LinuxFlaw</a></td>
        <td>This repo records all the vulnerabilities of linux software I have reproduced in my local workspace</td>
    </tr>
    <tr>
        <td><a href="https://github.com/xairy/kernel-exploits">xairy/kernel-exploits</a></td>
        <td>A bunch of proof-of-concept exploits for the Linux kernel</td>
    </tr>
</table>

## Hardening

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
    <tr>
        <td><a href="https://public.cyber.mil/stigs/">Security Technical Implementation Guides (STIGs)</a></td>
        <td>The Security Technical Implementation Guides (STIGs) are the configuration standards for DOD IA and IA-enabled devices/systems.</td>
    </tr>
    <tr>
        <td><a href="https://www.asd.gov.au/infosec/mitigationstrategies.htm">Strategies to Mitigate Cyber Security Incidents</a></td>
        <td>The Australian Signals Directorate (ASD) has developed prioritised mitigation strategies to help technical cyber security professionals in all organisations mitigate cyber security incidents. This guidance addresses targeted cyber intrusions, ransomware and external adversaries with destructive intent, malicious insiders, 'business email compromise' and industrial control systems.</td>
    </tr>
    <tr>
        <td><a href="https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-baselines">Windows Security Baseline</a></td>
        <td>A security baseline is a group of Microsoft-recommended configuration settings that explains their security impact. These settings are based on feedback from Microsoft security engineering teams, product groups, partners, and customers.</td>
    </tr>
</table>

## Hardware

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/ufrisk/pcileech">ufrisk/pcileech</a></td>
        <td>Direct Memory Access (DMA) Attack Software</td>
    </tr>
</table>

## Malware Analysis

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/activecm/rita">activecm/rita</a></td>
        <td> Real Intelligence Threat Analytics</td>
    </tr>
    <tr>
        <td><a href="https://github.com/adamkramer/rapid_env">adamkramer/rapid_env</a></td>
        <td>Rapid deployment of Windows environment (files, registry keys, mutex etc) to facilitate malware analysis</td>
    </tr>
    <tr>
        <td><a href="https://github.com/advanced-threat-research/IOCs">advanced-threat-research/IOCs</a></td>
        <td>Repository containing IOCs, MISP and Expert rules from our blogs</td>
    </tr>
    <tr>
        <td><a href="https://github.com/alexandreborges/malwoverview">alexandreborges/malwoverview</a></td>
        <td>Malwoverview.py is a simple tool to perform an initial and quick triage on either a directory containing malware samples or a specific malware sample</td>
    </tr>
    <tr>
        <td><a href="https://cse.google.com/cse/publicurl?cx=003248445720253387346:turlh5vi4xc">APT Groups, Operations and Malware Search Engine</td>
        <td>APT Groups, Operations and Malware Search Engine</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ashishb/android-malware">ashishb/android-malware</a></td>
        <td>Collection of android malware samples</td>
    </tr>
    <tr>
        <td><a href="https://avcaesar.malware.lu/">AVCaesar</a></td>
        <td>AVCaesar is a malware analysis engine and repository</td>
    </tr>
    <tr>
        <td><a href="https://github.com/blackorbird/APT_REPORT">blackorbird/APT_REPORT</a></td>
        <td>Interesting apt report collection and some special ioc express</td>
    </tr>
    <tr>
        <td><a href="https://github.com/CapacitorSet/box-js">CapacitorSet/box-js</a></td>
        <td>A tool for studying JavaScript malware</td>
    </tr>
    <tr>
        <td><a href="https://github.com/CERT-Polska/drakvuf-sandbox">CERT-Polska/drakvuf-sandbox</a></td>
        <td>DRAKVUF Sandbox - automated hypervisor-level malware analysis system</td>
    </tr>
	<tr>
		<td><a href="https://github.com/CheckPointSW/showstopper">CheckPointSW/showstopper</a></td>
		<td>ShowStopper is a tool for helping malware researchers explore and test anti-debug techniques or verify debugger plugins or other solutions that clash with standard anti-debug methods.</td>
	</tr>
    <tr>
        <td><a href="http://contagiodump.blogspot.com/">Contagio</a></td>
        <td>Malwarre dump</td>
    </tr>
    <tr>
        <td><a href="https://github.com/CriticalPathSecurity/Zeek-Intelligence-Feeds">CriticalPathSecurity/Zeek-Intelligence-Feeds</a></td>
        <td>Zeek-Formatted Threat Intelligence Feeds</td>
    </tr>
    <tr>
        <td><a href="https://www.malwaretracker.com/doc.php">Cryptam Document Scanner</a></td>
        <td>Encrypted/obfuscated malicious document analyzer</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cmu-sei/cyobstract">cmu-sei/cyobstract</a></td>
        <td>A tool to extract structured cyber information from incident reports.</td>
    </tr>
    	<tr>
		<td><a href="https://crxcavator.io/">CRXcavator</a></td>
		<td>CRXcavator automatically scans the entire Chrome Web Store every 3 hours and produces a quantified risk score for each Chrome Extension based on several factors.</td>
	</tr>
    <tr>
        <td><a href="https://github.com/countercept/snake">countercept/snake</a></td>
        <td>snake - a malware storage zoo</td>
    </tr>
    <tr>
        <td><a href="https://github.com/D4stiny/spectre">D4stiny/spectre</a></td>
        <td>A Windows kernel-mode rootkit that abuses legitimate communication channels to control a machine.</td>
    </tr>
    <tr>
        <td><a href="http://dasmalwerk.eu/">DAS MALWERK</a></td>
        <td>DAS MALWERK - your one stop shop for fresh malware samples</td>
    </tr>
    <tr>
        <td><a href="https://github.com/DoctorWebLtd/malware-iocs">DoctorWebLtd/malware-iocs</a></td>
        <td>This repository contains Indicators of Compromise (IOCs) related to our investigations.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/droidefense/engine">droidefense/engine</td>
        <td>Droidefense: Advance Android Malware Analysis Framework</td>
    </tr>
	<tr>
		<td><a href="https://github.com/ecstatic-nobel/Analyst-Arsenal">ecstatic-nobel/Analyst-Arsenal</a></td>
		<td>Phishing kits hunting</td>
	</tr>
	<tr>
		<td><a href="https://github.com/EFForg/yaya">EFForg/yaya</a></td>
		<td>Yet Another Yara Automaton - Automatically curate open source yara rules and run scans</td>
	</tr>
    <tr>
        <td><a href="https://github.com/eset/malware-ioc">eset/malware-ioc</a></td>
        <td>Indicators of Compromises (IOC) of our various investigations</td>
    </tr>
    <tr>
        <td><a href="https://certsocietegenerale.github.io/fame/">FAME</a></td>
        <td>FAME Automates Malware Evaluation</td>
    </tr>
	<tr>
		<td><a href="https://github.com/fireeye/flashmingo">fireeye/flashmingo</a></td>
		<td>Automatic analysis of SWF files based on some heuristics. Extensible via plugins.</td>
	</tr>
    <tr>
        <td><a href="https://github.com/fireeye/iocs">fireeye/iocs</a></td>
        <td>FireEye Publicly Shared Indicators of Compromise (IOCs)</td>
    </tr>
    <tr>
        <td><a href="https://github.com/felixweyne/imaginaryC2">felixweyne/imaginaryC2</a></td>
        <td>Imaginary C2 is a python tool which aims to help in the behavioral (network) analysis of malware. Imaginary C2 hosts a HTTP server which captures HTTP requests towards selectively chosen domains/IPs. Additionally, the tool aims to make it easy to replay captured Command-and-Control responses/served payloads.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/godaddy/procfilter">godaddy/procfilter</a></td>
        <td>A YARA-integrated process denial framework for Windows</td>
    </tr>
    <tr>
        <td><a href="https://github.com/fortinet/ips-bph-framework">ips-bph-framework</a></td>
        <td>BLACKPHENIX is an open source malware analysis automation framework composed of services, scripts, plug-ins, and tools and is based on a Command-and-Control (C&C) architecture</td>
    </tr>
    <tr>
        <td><a href="https://github.com/FortyNorthSecurity/WMImplant">FortyNorthSecurity/WMImplant</a></td>
        <td>This is a PowerShell based tool that is designed to act like a RAT. Its interface is that of a shell where any command that is supported is translated into a WMI-equivalent for use on a network/remote machine. WMImplant is WMI based.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/gen0cide/gscript">gen0cide/gscript</a></td>
        <td>Framework to rapidly implement custom droppers for all three major operating systems</td>
    </tr>
    <tr>
        <td><a href="https://github.com/glmcdona/Process-Dump">glmcdona/Process-Dump</a></td>
        <td>Windows tool for dumping malware PE files from memory back to disk for analysis.</td>
    </tr>
	<tr>
		<td><a href="https://github.com/google/vxsig">google/vxsig</a></td>
		<td>Automatically generate AV byte signatures from sets of similar binaries.</td>
	</tr>
    <tr>
        <td><a href="https://github.com/GoSecure/malboxes">GoSecure/malboxes</a></td>
        <td>Builds malware analysis Windows VMs so that you don't have to.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/GreatSCT/GreatSCT">GreatSCT/GreatSCT</a></td>
        <td>The project is called Great SCT (Great Scott). Great SCT is an open source project to generate application white list bypasses. This tool is intended for BOTH red and blue team</td>
    </tr>
    <tr>
        <td><a href="https://haveibeenemotet.com">Have I Been Emotet</a></etd>
        <td>Check if your email address or domain is involved in the Emotet malspam (name@domain.ext or domain.ext). Your address can be marked as a SENDER (FAKE or REAL), as a RECIPIENT or any combination of the three.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/hasherezade/libpeconv/tree/master/run_pe">hasherezade/libpeconv/runpe</a></td>
        <td>RunPE (aka Process Hollowing) is a well known technique allowing to injecting a new PE into a remote processes, imprersonating this process. The given implementation works for PE 32bit as well as 64bit.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/hasherezade/pe-sieve">hasherezade/pe-sieve</a></td>
        <td>Scans a given process, searching for the modules containing in-memory code modifications. When found, it dumps the modified PE.</td>
    </tr>
    <tr>
        <td><a href="https://tria.ge/">Hatching Triage</a></td>
        <td>Triage is our state-of-the-art malware analysis sandbox designed for cross-platform support (Windows, Android, Linux, and macOS), high-volume malware analysis capabilities, and configuration extraction for numerous malware families.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/hegusung/AVSignSeek">hegusung/AVSignSeek</a></td>
        <td>Tool written in python3 to determine where the AV signature is located in a binary/payload</td>
    </tr>
        <tr>
        <td><a href="https://github.com/hlldz/SpookFlare">hlldz/SpookFlare</a></td>
        <td>Loader, dropper generator with multiple features for bypassing client-side and network-side countermeasures.</td>
    </tr>
    <tr>
        <td><a href="https://www.hybrid-analysis.com/">Hybrid-Analysis</a></td>
        <td>Free Automated Malware Analysis Service</td>
    </tr>
	<tr>
		<td><a href="https://github.com/InQuest/ThreatIngestor">InQuest/ThreatIngestor</a></td>
		<td>An extendable tool to extract and aggregate IOCs from threat feeds.</td>
	</tr>
    <tr>
        <td><a href="https://iris-h.malwageddon.com/">IRIS-H</a></td>
        <td>IRIS-H is an online digital forensics tool that performs automated static analysis of files stored in a directory-based or strictly structured formats.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/jgamblin/Mirai-Source-Code">jgamblin/Mirai-Source-Code</a></td>
        <td>Leaked Mirai Source Code for Research/IoC Development Purposes.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/JPCERTCC/MalConfScan">jgamblin/JPCERTCC/MalConfScan</a></td>
        <td>Volatility plugin for extracts configuration data of known malware</td>
    </tr>
    <tr>
        <td><a href="https://github.com/KasperskyLab/klara">KasperskyLab/klara</a></td>
        <td>Klara project is aimed at helping Threat Intelligence researechers hunt for new malware using Yara.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/katjahahn/PortEx">katjahahn/PortEx</a></td>
        <td>Java library to analyse Portable Executable files with a special focus on malware analysis and PE malformation robustness</td>
    </tr>
    <tr>
        <td><a href="https://koodous.com">Koodous</a></td>
        <td>Koodous is a collaborative platform that combines the power of online analysis tools with social interactions between the analysts over a vast APKs repository.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/LordNoteworthy/al-khaser">LordNoteworthy/al-khaser</a></td>
        <td>Public malware techniques used in the wild: Virtual Machine, Emulation, Debuggers, Sandbox detection.</td>
    </tr>
    <tr>
        <td><a href="https://objective-see.com/malware.html">Mac Malware</a></td>
        <td>Mac Malware by Objective-See</td>
    </tr>
    <tr>
        <td><a href="https://github.com/marcosd4h/memhunter">marcosd4h/memhunter</a></td>
        <td>Live hunting of code injection techniques</td>
    </tr>
    <tr>
        <td><a href="http://malc0de.com/database/">Malc0de database</a></td>
        <td>Malc0de database</td>
    </tr>
    <tr>
        <td><a href="https://github.com/maliceio/malice">maliceio/malice</a></td>
        <td>Malice's mission is to be a free open source version of VirusTotal that anyone can use at any scale from an independent researcher to a fortune 500 company.</td>
    </tr>
    <tr>
        <td><a href="https://malpedia.caad.fkie.fraunhofer.de/">Malpedia</a></td>
        <td>The primary goal of Malpedia is to provide a resource for rapid identification and actionable context when investigating malware. Openness to curated contributions shall ensure an accountable level of quality in order to foster meaningful and reproducible research.</td>
    </tr>
    <tr>
        <td><a href="https://malshare.com/">MalShare</a></td>
        <td>A free Malware repository providing researchers access to samples, malicous feeds, and Yara results</td>
    </tr>
    <tr>
        <td><a href="https://bazaar.abuse.ch/browse/">MalwareBazaar Database</a></td>
        <td>MalwareBazaar is a project operated by abuse.ch. The purpose of the project is to collect and share malware samples, helping IT-security researchers and threat analyst protecting their constituency and customers from cyber threats.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/MalwareCantFly/Vba2Graph/">MalwareCantFly/Vba2Graph</a></td>
        <td>Vba2Graph - Generate call graphs from VBA code, for easier analysis of malicious documents.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/malwaredllc/byob">malwaredllc/byob</a></td>
        <td>BYOB (Build Your Own Botnet)</td>
    </tr>
    <tr>
        <td><a href="https://github.com/malwareinfosec/EKFiddle">malwareinfosec/EKFiddle</a></td>
        <td>A framework based on the Fiddler web debugger to study Exploit Kits, malvertising and malicious traffic in general.</td>
    </tr>
    <tr>
        <td><a href="https://www.maltiverse.com/search">Malwaretiverse</a></td>
        <td>maltiverse - Connect the dots - The definitive IoC search engine</td>
    </tr>
    <tr>
        <td><a href="https://malwares.github.io/">Malwares</a></td>
        <td>Malware SRC Database</td>
    </tr>
    <tr>
        <td><a href="https://marcoramilli.com/malware/">Malware Static Analysis</a></td>
        <td>The following interface stands in front of a live engine which takes binary files and runs them against a pletora of hundreds YARA rules.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/marcoramilli/PhishingKitTracker">marcoramilli/PhishingKitTracker</a></td>
        <td>An extensible and freshly updated collection of phishingkits for forensics and future analysis topped with simple stats</td>
    </tr>
    <tr>
        <td><a href="https://github.com/matterpreter/DefenderCheck">matterpreter/DefenderCheck</a></td>
        <td>Identifies the bytes that Microsoft Defender flags on.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/MinervaLabsResearch/Mystique">MinervaLabsResearch/Mystique</a></td>
        <td>Mystique may be used to discover infection markers that can be used to vaccinate endpoints against malware. It receives as input a malicious sample and automatically generates a list of mutexes that could be used to as "vaccines" against the sample</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mitchellkrogza/Phishing.Database">mitchellkrogza/Phishing.Database</a></td>
        <td>Phishing Domains, urls websites and threats database. We use the PyFunceble testing tool to validate the status of all known Phishing domains and provide stats to reveal how many unique domains used for Phishing are still active</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mohamedaymenkarmous/alienvault-otx-api-html">mohamedaymenkarmous/alienvault-otx-api-html</a></td>
        <td>AlienVault OTX API-based project with HTML (pure HTML or mixed PNG screenshots) reports pages that looks like the real AlienVault OTX website</td>
    </tr>
    <tr>
        <td><a href="https://github.com/NavyTitanium/Fake-Sandbox-Artifacts">NavyTitanium/Fake-Sandbox-Artifacts</a></td>
        <td>This script allows you to create various artifacts on a bare-metal Windows computer in an attempt to trick malwares that looks for VM or analysis tools</td>
    </tr>
    <tr>
        <td><a href="https://github.com/nbeede/BoomBox">nbeede/BoomBox</a></td>
        <td>Automatic deployment of Cuckoo Sandbox malware lab using Packer and Vagrant</td>
    </tr>
    <tr>
        <td><a href="https://github.com/nbulischeck/tyton">nbulischeck/tyton</a></td>
        <td>Linux Kernel-Mode Rootkit Hunter for 4.4.0-31+</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Neo23x0/APTSimulator">Neo23x0/APTSimulator</a></td>
        <td>A toolset to make a system look as if it was the victim of an APT attack</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Neo23x0/exotron">Neo23x0/exotron</a></td>
        <td>Sandbox feature upgrade with the help of wrapped samples</td>
    </tr>
    <tr>
        <td><a href="https://github.com/nsmfoo/antivmdetection">nsmfoo/antivmdetection</a></td>
        <td>Script to create templates to use with VirtualBox to make vm detection harder</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ntddk/virustream">ntddk/virustream</a></td>
        <td>A script to track malware IOCs with OSINT on Twitter.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/OALabs/BlobRunner">OALabs/BlobRunner</a></td>
        <td>Quickly debug shellcode extracted during malware analysis</td>
    </tr>
    <tr>
        <td><a href="https://github.com/OALabs/PyIATRebuild">OALabs/PyIATRebuild</a></td>
        <td>Automatically rebuild Import Address Table for dumped PE file. With python bindings!</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ohjeongwook/PowerShellRunBox">ohjeongwook/PowerShellRunBox</a></td>
        <td>Dynamic PowerShell analysis framework</td>
    </tr>
	<tr>
		<td><a href="https://github.com/outflanknl/EvilClippy">outflanknl/EvilClippy</a></td>
		<td>A cross-platform assistant for creating malicious MS Office documents. Can hide VBA macros, stomp VBA code (via P-Code) and confuse macro analysis tools. Runs on Linux, OSX and Windows.</td>
	</tr>
    <tr>
        <td><a href="https://github.com/P4T12ICK/ypsilon">P4T12ICK/ypsilon</a></td>
        <td>Ypsilon is an Automated Security Use Case Testing Environment using real malware to test SIEM use cases in an closed environment. Different tools such as Ansible, Cuckoo, VirtualBox, Splunk and ELK are combined to determine the quality of a SIEM use case by testing any number of malware against a SIEM use case. Finally, a test report is generated giving insight to the quality of an use case.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/pan-unit42/iocs">pan-unit42/iocs</a></td>
        <td>Indicators from Unit 42 Public Reports</td>
    </tr>
    <tr>
        <td><a href="https://github.com/phage-nz/ph0neutria">phage-nz/ph0neutria</a></td>
        <td>ph0neutria is a malware zoo builder that sources samples straight from the wild. Everything is stored in Viper for ease of access and manageability.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/PwCUK-CTO/rtfsig">PwCUK-CTO/rtfsig</a></td>
        <td>A tool to help malware analysts signature unique parts of RTF documents</td>
    </tr>
    <tr>
        <td><a href="https://github.com/InQuest/python-iocextract">python-iocextract</a></td>
        <td>Advanced Indicator of Compromise (IOC) extractor</td>
    </tr>
    <tr>
        <td><a href="https://github.com/quarkslab/irma">quarkslab/irma</a></td>
        <td>IRMA is an asynchronous & customizable analysis system for suspicious files.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/quasar/QuasarRAT">quasar/QuasarRAT</a></td>
        <td>Quasar is a fast and light-weight remote administration tool coded in C#. Providing high stability and an easy-to-use user interface, Quasar is the perfect remote administration solution for you.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/rastrea2r/rastrea2r">rastrea2r/rastrea2r</a></td>
        <td>Collecting & Hunting for IOCs with gusto and style</td>
    </tr>
    <tr>
        <td><a href="https://github.com/SafeBreach-Labs/mkmalwarefrom">SafeBreach-Labs/mkmalwarefrom</a></td>
        <td>Proof-of-concept two-stage dropper generator that uses bits from external sources</td>
    </tr>
    <tr>
        <td><a href="https://malware.sekoia.fr/new">SEKOIA Dropper Analysis</a></td>
        <td>SEKOIA Dropper Analysis</td>
    </tr>
    <tr>
        <td><a href="https://github.com/SpamScope/spamscope">SpamScope/spamscope</a></td>
        <td>Fast Advanced Spam Analysis Tool</td>
    </tr>
    <tr>
        <td><a href="https://github.com/SpiderLabs/IOCs-IDPS">SpiderLabs/IOCs-IDPS</a></td>
        <td>This repository will hold PCAP IOC data related with known malware samples (owner: Bryant Smith)</td>
    </tr>
    <tr>
        <td><a href="https://github.com/t4d/PhishingKitHunter">t4d/PhishingKitHunter</a></td>
        <td>Find phishing kits which use your brand/organization's files and image.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ThisIsLibra/MalPull">ThisIsLibra/MalPull</a></td>
        <td>A CLI interface to search for a MD-5/SHA-1/SHA-256 hash on multiple malware databases and download the sample from the first hit</td>
    </tr>
    <tr>
        <td><a href="https://threatshare.io/">ThreatShare</a></td>
        <td>ThreatShare is an advanced threat tracker that publicly tracks command & control servers for malware.</td>
    </tr>
	<tr>
		<td><a href="https://github.com/tomchop/malcom">tomchop/malcom</a></td>
		<td>Malcom - Malware Communications Analyzer</td>
	</tr>
    <tr>
        <td><a href="https://pan-unit42.github.io/playbook_viewer/">UNIT 42: Playbook Viewver</a></td>
        <td>Viewing PAN Unit 42's adversary playbook via web interface</td>
    </tr>
    <tr>
        <td><a href="https://www.unpac.me/#/">UNPACME</a></td>
        <td>An automated malware unpacking service from OpenAnalysis</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ytisf/theZoo">ytisf/theZoo</a></td>
        <td>A repository of LIVE malwares for your own joy and pleasure</td>
    </tr>
    <tr>
        <td><a href="https://beta.virusbay.io/">VirusBay</a></td>
        <td>VirusBay is a web-based, collaboration platform that connects security operations center (SOC) professionals with relevant malware researchers</td>
    </tr>
    <tr>
        <td><a href="https://virusshare.com/">VirusShare</a></td>
        <td>VirusShare.com is a repository of malware samples to provide security researchers, incident responders, forensic analysts, and the morbidly curious access to samples of live malicious code</td>
    </tr>
    <tr>
        <td><a href="http://vxvault.net/ViriList.php">VX Vault</a></td>
        <td>VX Vault</td>
    </tr>
	<tr>
		<td><a href="https://github.com/zerosum0x0/smbdoor">zerosum0x0/smbdoor</a></td>
		<td>kernel backdoor via registering a malicious SMB handler</td>
	</tr>
</table>

## Mobile Security

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/ac-pm/Inspeckage">ac-pm/Inspeckage</a></td>
        <td>Android Package Inspector - dynamic analysis with api hooks, start unexported activities and more. (Xposed Module)</td>
    </tr>
    <tr>
        <td><a href="https://air.line.me/air/product#tab_airgo">AIR GO</a></td>
        <td>AIR GO detects obfuscation, vulnerabilities, open-source license issues, and malware by analyzing mobile apps and websites. It uses industry-leading technology to detect security threats and provide an improvement plan.</td>
    </tr>
    <tr>
        <td><a href="https://www.apkdetect.com/">apkdetect</a></td>
        <td>Android malware analysis and classification platform</td>
    </tr>
    <tr>
        <td><a href="https://ibotpeaches.github.io/Apktool/">Apktool</a></td>
        <td>A tool for reverse engineering Android apk files</td>
    </tr>
    <tr>
        <td><a href="https://github.com/chaitin/passionfruit">chaitin/passionfruit</a></td>
        <td>Simple iOS app blackbox assessment tool. Powered by frida.re and vuejs.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/dpnishant/appmon">dpnishant/appmon</a></td>
        <td>AppMon is an automated framework for monitoring and tampering system API calls of native macOS, iOS and android apps. It is based on Frida.</td>
    </tr>
    <tr>
        <td><a href="http://www.cycript.org/">Cycript</a></td>
        <td>Cycript allows developers to explore and modify running applications on either iOS or Mac OS X using a hybrid of Objective-C++ and JavaScript syntax through an interactive console that features syntax highlighting and tab completion</td>
    </tr>
    <tr>
        <td><a href="https://github.com/dmayer/idb">dmayer/idb</a></td>
        <td>idb is a tool to simplify some common tasks for iOS pentesting and research</td>
    </tr>
    <tr>
        <td><a href="https://labs.mwrinfosecurity.com/tools/drozer/">Drozer</a></td>
        <td>Comprehensive security and attack framework for Android</td>
    </tr>
    <tr>
        <td><a href="https://github.com/frida/frida">frida/frida</a></td>
        <td>Dynamic instrumentation toolkit for developers, reverse-engineers, and security researchers.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/iSECPartners/Android-SSL-TrustKiller">iSECPartners/Android-SSL-TrustKiller</a></td>
        <td>Bypass SSL certificate pinning for most applications</td>
    </tr>
    <tr>
        <td><a href="https://github.com/KJCracks/Clutch">KJCracks/Clutch</a></td>
        <td>Fast iOS executable dumper</td>
    </tr>
    <tr>
        <td><a href="https://github.com/linkedin/qark">linkedin/qark</a></td>
        <td>Tool to look for several security related Android application vulnerabilities</td>
    </tr>
    <tr>
        <td><a href="https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security">m0bilesecurity/RMS-Runtime-Mobile-Security</a></td>
        <td>Runtime Mobile Security (RMS) is a powerful web interface that helps you to manipulate Android Java Classes and Methods at Runtime</td>
    </tr>
    <tr>
        <td><a href="https://github.com/MobSF/Mobile-Security-Framework-MobSF">MobSF/Mobile-Security-Framework-MobSF</a></td>
        <td>Mobile Security Framework is an automated, all-in-one mobile application (Android/iOS/Windows) pen-testing framework capable of performing static analysis, dynamic analysis, malware analysis and web API testing</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mwrlabs/needle">mwrlabs/needle</a></td>
        <td>The iOS Security Testing Framework</td>
    </tr>
    <tr>
        <td><a href="https://github.com/nccgroup/house">nccgroup/house</a></td>
        <td>A runtime mobile application analysis toolkit with a Web GUI, powered by Frida, written in Python.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/nygard/class-dump">nygard/class-dump</a></td>
        <td>Generate Objective-C headers from Mach-O files</td>
    </tr>
    <tr>
        <td><a href="https://github.com/pxb1988/dex2jar">pxb1988/dex2jar</a></td>
        <td>Tools to work with android .dex and java .class files</td>
    </tr>
    <tr>
        <td><a href="https://github.com/quark-engine/quark-engine">quark-engine/quark-engine</a></td>
        <td>An Obfuscation-Neglect Android Malware Scoring System</td>
    </tr>
    <tr>
        <td><a href="https://github.com/RealityNet/kobackupdechttps://github.com/RealityNet/kobackupdec">RealityNet/kobackupdec</a></td>
        <td>Huawei backup decryptor</td>
    </tr>
    <tr>
        <td><a href="https://github.com/sensepost/objection">sensepost/objection</a></td>
        <td>objection is a runtime mobile exploration toolkit, powered by Frida. It was built with the aim of helping assess mobile applications and their security posture without the need for a jailbroken or rooted mobile device.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/skylot/jadx">skylot/jadx</a></td>
        <td>Dex to Java decompiler</td>
    </tr>
    <tr>
        <td><a href="https://github.com/stefanesser/dumpdecrypted">stefanesser/dumpdecrypted</a></td>
        <td>Dumps decrypted mach-o files from encrypted iPhone applications from memory to disk. This tool is necessary for security researchers to be able to look under the hood of encryption.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/swdunlop/AndBug">swdunlop/AndBug</a></td>
        <td>Android Debugging Library</td>
    </tr>
    <tr>
        <td><a href="https://github.com/tcurdt/iProxy">tcurdt/iProxy</a></td>
        <td>Let's you connect your laptop to the iPhone to surf the web.</td>
    </tr>
</table>

## Network Security

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/aol/moloch">aol/moloch</a></td>
        <td>Moloch is an open source, large scale, full packet capturing, indexing, and database system</td>
    </tr>
    <tr>
        <td><a href="https://github.com/austin-taylor/flare">austin-taylor/flare</a></td>
        <td>An analytical framework for network traffic and behavioral analytics</td>
    </tr>
    <tr>
        <td><a href="https://github.com/crowdsecurity/crowdsec/">crowdsecurity/crowdsec/</a></td>
        <td>Crowdsec - An open-source, lightweight agent to detect and respond to bad behaviours. It also automatically benefits from our global community-wide IP reputation database.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/blechschmidt/massdns">blechschmidt/massdns</a></td>
        <td>A high-performance DNS stub resolver for bulk lookups and reconnaissance (subdomain enumeration)</td>
    </tr>
    <tr>
        <td><a href="https://github.com/byt3bl33d3r/MITMf">byt3bl33d3r/MITMf</a></td>
        <td>Framework for Man-In-The-Middle attacks</td>
    </tr>
    <tr>
        <td><a href="https://github.com/dhoelzer/ShowMeThePackets">dhoelzer/ShowMeThePackets</a></td>
        <td>Useful network monitoring, analysis, and active response tools used or mentioned in the SANS SEC503 course</td>
    </tr>
    <tr>
        <td><a href="https://dnsdumpster.com/">DNSdumpster.com</a></td>
        <td>dns recon & research, find & lookup dns records</td>
    </tr>
    <tr>
        <td><a href="https://github.com/eldraco/domain_analyzer/">eldraco/domain_analyzer</a></td>
        <td>Analyze the security of any domain by finding all the information possible. Made in python.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/fireeye/flare-fakenet-ng">fireeye/flare-fakenet-ng</a></td>
        <td>FakeNet-NG - Next Generation Dynamic Network Analysis Tool</td>
    </tr>
    <tr>
        <td><a href="https://github.com/infobyte/evilgrade">infobyte/evilgrade</a></td>
        <td>Evilgrade is a modular framework that allows the user to take advantage of poor upgrade implementations by injecting fake updates. It comes with pre-made binaries (agents), a working default configuration for fast pentests, and has it's own WebServer and DNSServer modules. Easy to set up new settings, and has an autoconfiguration when new binary agents are set.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/joswr1ght/cowpatty">joswr1ght/cowpatty</a></td>
        <td>coWPAtty: WPA2-PSK Cracking</td>
    </tr>
    <tr>
        <td><a href="https://github.com/joswr1ght/nm2lp">joswr1ght/nm2lp</a></td>
        <td>Convert Windows Netmon Monitor Mode Wireless Packet Captures to Libpcap Format</td>
    </tr>
    <tr>
        <td><a href="https://github.com/michenriksen/aquatone">michenriksen/aquatone</a></td>
        <td>AQUATONE is a set of tools for performing reconnaissance on domain names. It can discover subdomains on a given domain by using open sources as well as the more common subdomain dictionary brute force approach. After subdomain discovery, AQUATONE can then scan the hosts for common web ports and HTTP headers, HTML bodies and screenshots can be gathered and consolidated into a report for easy analysis of the attack surface.</td>
    </tr>
    <tr>
        <td><a href="https://scan.netlab.360.com">NetworkScan Mon</a></td>
        <td>NetworkScan Monitor by Netlab 360</td>
    </tr>
    <tr>
        <td><a href="https://packettotal.com/">PacketTotal</a></td>
        <td>A free, online PCAP analysis engine</td>
    </tr>
    <tr>
        <td><a href="https://github.com/sensepost/routopsy">sensepost/routopsy</a></td>
        <td>Routopsy is a toolkit built to attack often overlooked networking protocols. Routopsy currently supports attacks against Dynamic Routing Protocols (DRP) and First-Hop Redundancy Protocols (FHRP).</td>
    </tr>
    <tr>
        <td><a href="https://github.com/USArmyResearchLab/Dshell">USArmyResearchLab/Dshell</a></td>
        <td>An extensible network forensic analysis framework. Enables rapid development of plugins to support the dissection of network packet captures.</td>
    </tr>
    <tr>
        <td><a href="https://wigle.net/">WiGLE</a></td>
        <td>Maps and database of 802.11 wireless networks, with statistics, submitted by wardrivers, netstumblers, and net huggers.</td>
    </tr>
    <tr>
        <td><a href="https://wireedit.com/">WireEdit</a></td>
        <td>First-Of-A-Kind And The Only Full Stack WYSIWYG Pcap Editor</td>
    </tr>
    <tr>
        <td><a href="https://zmap.io/">The ZMap Project</a></td>
        <td>The ZMap Project is a collection of open source tools that enable researchers to perform large-scale studies of the hosts and services that compose the public Internet.</td>
    </tr>
</table>

## Open-source Intelligence (OSINT) 

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/althonos/InstaLooter">althonos/InstaLooter</a></td>
        <td>Another API-less Instagram pictures and videos downloader.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/arch4ngel/peasant">arch4ngel/peasant</a></td>
        <td>LinkedIn reconnaissance tool</td>
    </tr>
    <tr>
        <td><a href="https://github.com/byt3bl33d3r/WitnessMe">byt3bl33d3r/WitnessMe</a></td>
        <td>Web Inventory tool, takes screenshots of webpages using Pyppeteer (headless Chrome/Chromium) and provides some extra bells & whistles to make life easier.</td>
    </tr>
    <tr>
        <td><a href="https://cellidfinder.com/">CellID Finder</a></td>
        <td>Find GSM base stations cell id coordinates</a></td>
    </tr>
    <tr>
        <td><a href="https://www.cellmapper.net">CellMapper</a></td>
        <td>Cellular Coverage and Tower Map</a></td>
    </tr>
    <tr>
        <td><a href="https://crt.sh/">Certificate Search</a></td>
        <td>crt.sh | Certificate</td>
    </tr>
    <tr>
        <td><a href="https://github.com/danieleperera/onioningestor">danieleperera/onioningestor</a></td>
        <td>An extendable tool to Collect, Crawl and Monitor onion sites on tor network and index collected information on Elasticsearch</td>
    </tr>
    <tr>
        <td><a href="https://www.dargle.net/search">Dargle</a></td>
        <td>Dargle serves as a data aggregation platform for dark web domains. Hidden services on the dark web prove difficult to navigate, but by crawling the clear web, one can accumulate a directory of sorts for these hidden services.</td>
    </tr>
    <tr>
        <td><a href="https://dark.fail/">dark.fail: Is a darknet site online?</a></td>
        <td>dark.fail: Is a darknet site online?</td>
    </tr>
    <tr>
        <td><a href="https://domainbigdata.com/">DomainBigData</a></td>
        <td>DomainBigData is a big database of domains and whois records</td>
    </tr>
    <tr>
        <td><a href="https://github.com/danieliu/play-scraper">danieliu/play-scraper</a></td>
        <td>A web scraper to retrieve application data from the Google Play Store.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/DataSploit/datasploit">DataSploit/datasploit</a></td>
        <td>An #OSINT Framework to perform various recon techniques on Companies, People, Phone Number, Bitcoin Addresses, etc., aggregate all the raw data, and give data in multiple formats.</td>
    </tr>
    <tr>
        <td><a href="https://tools.epieos.com/google-account.php">Epieos Tools - Google Account Finder</a></td>
        <td>An online tool to retrieve sensitive information like google maps reviews, public photos, displayed name, usage of google services such as YouTube, Hangouts</td>
    </tr>
    <tr>
        <td><a href="https://fofa.so/">FOFA Pro</a></td>
        <td>The Cyberspace Search Engine, Security Situation Awareness</td>
    </tr>
    <tr>
        <td><a href="https://viz.greynoise.io/">GreyNoise Visualizer</a></td>
        <td>GreyNoise Visualizer</td>
    </tr>
    <tr>
        <td><a href="https://github.com/haccer/twint">haccer/twint</a></td>
        <td>An advanced Twitter scraping & OSINT tool written in Python that doesn't use Twitter's API, allowing you to scrape a user's followers, following, Tweets and more while evading most API limitations.</td>
    </tr>
    <tr>
        <td><a href="https://iknowwhatyoudownload.com/en/peer/">I Know What You Download</a></td>
        <td>Torrent downloads and distributions for IP</td>
    </tr>
    <tr>
        <td><a href="https://www.immuniweb.com/radar/">ImmuniWeb</a></td>
        <td>Domain Security Test | Detect Dark Web Exposure, Phishing, Squatting and Trademark Infringement</td>
    </tr>
    <tr>
        <td><a href="https://intelx.io/">IntelligenceX</a></td>
        <td>Search Tor, I2P, data leaks, public web.| </td>
    </tr>
    <tr>
        <td><a href="https://github.com/InQuest/omnibus">InQuest/omnibus</a></td>
        <td>The OSINT Omnibus</td>
    </tr>
    <tr>
		<td><a href="https://github.com/intelowlproject/IntelOwl">intelowlproject/IntelOwl</a></td>
		<td>Intel Owl: analyze files, domains, IPs in multiple ways from a single API at scale</td>
	</tr>
    <tr>
        <td><a href="https://github.com/iptv-org/iptv">iptv-org/iptv</a></td>
        <td>Collection of 8000+ publicly available IPTV channels from all over the world</td>
    </tr>
    <tr>
        <td><a href="https://github.com/jofpin/trape">jofpin/trape</a></td>
        <td>People tracker on the Internet: OSINT analysis and research tool.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/lanrat/certgraph">lanrat/certgraph</a></td>
        <td>An open source intelligence tool to crawl the graph of certificate Alternate Names</td>
    </tr>
    <tr>
	<td><a href="https://leakix.net/">LeakIX</a></td>
	<td>This project goes around the internet and finds services to index them.</td></tr>
    <tr>
        <td><a href="https://github.com/leapsecurity/InSpy">leapsecurity/InSpy</a></td>
        <td>A python based LinkedIn enumeration tool</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ninoseki/mihari">ninoseki/mihari</a></td>
        <td>A helper to run OSINT queries & manage results continuously</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mxrch/ghunt">mxrch/ghunt</a></td>
        <td>GHunt is an OSINT tool to extract a lot of informations of someone's Google Account email.</td>
    </tr>
    <tr>
        <td><a href="https://data.occrp.org/">OCCRP Data</a></td>
        <td>Search 102m public records and leaks from 179 sources</td>
    </tr>
    <tr>
        <td><a href="https://opencellid.org">OpenCelliD</a></td>
        <td>OpenCelliD - Largest Open Database of Cell Towers & Geolocation - by Unwired Labs</td>
    </tr>
    <tr>
        <td><a href="https://github.com/OWASP/Amass">OWASP/Amass</a></td>
        <td>In-depth Attack Surface Mapping and Asset Discovery</td>
    </tr>
    <tr>
        <td><a href="https://psbdmp.ws/">Pastebin dump collection</a></td>
        <td>Pastebin dump collection</td>
    </tr>
    <tr>
        <td><a href="https://phonebook.cz/">Phonebook.cz</a></td>
        <td>Phonebook lists all domains, email addresses, or URLs for the given input domain.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/s-rah/onionscan">s-rah/onionscan</a></td>
        <td>OnionScan is a free and open source tool for investigating the Dark Web.</td>
    </tr>
    <tr>
        <td><a href="https://same.energy/">same.energy</a></td>
        <td>Tweet Search Engine</td>
    </tr>
    <tr>
		<td><a href="https://github.com/sshell/reddit-analyzer">sshell/reddit-analyzer</a></td>
		<td>find out when and where someone is posting to reddit</td>
	</tr>
	</tr>
    <tr>
        <td><a href="http://www.spiderfoot.net/">SpiderFoot</a></td>
        <td>SpiderFoot - Opensource Intelligence Automation</td>
    </tr>
    <tr>
        <td><a href="https://github.com/superhedgy/AttackSurfaceMapper">superhedgy/AttackSurfaceMapper</a></td>
        <td>AttackSurfaceMapper is a tool that aims to automate the reconnaissance process.</td>
    </tr>
	<tr>
		<td><a href="https://hackertarget.com/recon-ng-tutorial/">Recon-NG</a></td>
		<td>Recon-ng is a reconnaissance tool with an interface similar to Metasploit. Running recon-ng from the command line you enter a shell like environment where you can configure options, perform recon and output results to different report types.</td>
	</tr>
    <tr>
        <td><a href="https://github.com/WebBreacher/WhatsMyName">WebBreacher/WhatsMyName</a></td>
        <td>This repository has the unified data required to perform user enumeration on various websites. Content is in a JSON file and can easily be used in other projects.</td>
    </tr>
    <tr>
        <td><a href="https://whatsmyname.app/">WhatsMyName Web</a></td>
        <td>This tool allows you to enumerate usernames across many websites</td>
    </tr>
	<tr>
		<td><a href="https://github.com/woj-ciech/kamerka">woj-ciech/kamerka</a></td>
		<td>Build interactive map of cameras from Shodan</td>
	</tr>
    <tr>
        <td><a href="https://github.com/woj-ciech/SocialPath">woj-ciech/SocialPath</a></td>
        <td>Track users across social media platform</td>
    </tr>
</table>

## Password Cracking and Wordlists

<table>
    <tr>
        <td><a href="https://github.com/berzerk0/Probable-Wordlists">berzerk0/Probable-Wordlists</a></td>
        <td>Wordlists sorted by probability originally created for password generation and testing - make sure your passwords aren't popular!</td>
    </tr>
    <tr>
        <td><a href="https://github.com/byt3bl33d3r/SprayingToolkit">byt3bl33d3r/SprayingToolkit</a></td>
        <td>Scripts to make password spraying attacks against Lync/S4B & OWA a lot quicker, less painful and more efficient</td>
    </tr>
    <tr>
        <td><a href="https://github.com/fireeye/gocrack">fireeye/gocrack</a></td>
        <td>GoCrack provides APIs to manage password cracking tasks across supported cracking engines.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/sc0tfree/mentalist">sc0tfree/mentalist</a></td>
        <td>Mentalist is a graphical tool for custom wordlist generation. It utilizes common human paradigms for constructing passwords and can output the full wordlist as well as rules compatible with Hashcat and John the Ripper.</td>
    </tr>
	<tr>
		<td><a href="https://github.com/trustedsec/hate_crack">trustedsec/hate_crack</a></td>
		<td>A tool for automating cracking methodologies through Hashcat from the TrustedSec team.</td>
	</tr>
    <tr>
        <td><a href="https://github.com/danielmiessler/SecLists">danielmiessler/SecLists</a></td>
        <td>SecLists is the security tester's companion. It is a collection of multiple types of lists used during security assessments. List types include usernames, passwords, URLs, sensitive data grep strings, fuzzing payloads, and many more.</td>
    </tr>
</table>

## Post Exploitation

<table>
    <tr>
        <td><a href="https://github.com/0xbadjuju/Tokenvator">0xbadjuju/Tokenvator</a></td>
        <td>A tool to elevate privilege with Windows Tokens</td>
    </tr>
    <tr>
        <td><a href="https://github.com/3xpl01tc0d3r/Callidus">3xpl01tc0d3r/Callidus</a></td>
        <td>It is developed using .net core framework in C# language. Allows operators to leverage O365 services for establishing command & control communication channel. It usages Microsoft Graph APIs for communicating with O365 services.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/411Hall/JAWS">411Hall/JAWS</a></td>
        <td>JAWS is PowerShell script designed to help penetration testers (and CTFers) quickly identify potential privilege escalation vectors on Windows systems. It is written using PowerShell 2.0 so 'should' run on every Windows version since Windows 7.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/api0cradle/LOLBAS">api0cradle/LOLBAS</a></td>
        <td>Living Off The Land Binaries and Scripts (and now also Libraries)</td>
    </tr>
    <tr>
        <td><a href="https://github.com/api0cradle/UltimateAppLockerByPassList">api0cradle/UltimateAppLockerByPassList</a></td>
        <td>The goal of this repository is to document the most common techniques to bypass AppLocker.</td>
    </tr>
	<tr>
		<td><a href="https://github.com/Arvanaghi/SessionGopher">Arvanaghi/SessionGopher</a></td>
		<td>SessionGopher is a PowerShell tool that uses WMI to extract saved session information for remote access tools such as WinSCP, PuTTY, SuperPuTTY, FileZilla, and Microsoft Remote Desktop. It can be run remotely or locally.</td>
	</tr>
    <tr>
        <td><a href="https://github.com/BC-SECURITY/Empire/">BC-SECURITY/Empire</a></td>
        <td>Empire is a PowerShell and Python post-exploitation agent.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/besimorhino/powercat">besimorhino/powercat</a></td>
        <td>netshell features all in version 2 powershell</td>
    </tr>
    <tr>
        <td><a href="https://github.com/bohops/GhostBuild">bohops/GhostBuild</a></td>
        <td>GhostBuild is a collection of simple MSBuild launchers for various GhostPack/.NET projects</td>
    </tr>
    <tr>
        <td><a href="https://github.com/byt3bl33d3r/CrackMapExec">byt3bl33d3r/CrackMapExec</a></td>
        <td>A swiss army knife for pentesting networks</td>
    </tr>
    <tr>
        <td><a href="https://github.com/byt3bl33d3r/SILENTTRINITY">byt3bl33d3r/SILENTTRINITY</a></td>
        <td>An asynchronous, collaborative post-exploitation agent powered by Python and .NET's DLR</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cobbr/Covenant">cobbr/Covenant</a></td>
        <td> Covenant is a .NET command and control framework that aims to highlight the attack surface of .NET, make the use of offensive .NET tradecraft easier, and serve as a collaborative command and control platform for red teamers.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cobbr/SharpSploit">cobbr/SharpSploit</a></td>
        <td>SharpSploit is a .NET post-exploitation library written in C#</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Cn33liz/p0wnedShell">Cn33liz/p0wnedShell</a></td>
        <td>p0wnedShell is an offensive PowerShell host application written in C# that does not rely on powershell.exe but runs powershell commands and functions within a powershell runspace environment (.NET)</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Cybellum/DoubleAgent">Cybellum/DoubleAgent</a></td>
        <td>DoubleAgent is a new Zero-Day technique for injecting code and maintaining persistence on a machine (i.e. auto-run).</td>
    </tr>
    <tr>
        <td><a href="https://github.com/danielbohannon/Invoke-DOSfuscation">danielbohannon/Invoke-DOSfuscation</a></td>
        <td>Cmd.exe Command Obfuscation Generator & Detection Test Harness</td>
    </tr>
    <tr>
        <td><a href="https://github.com/danielbohannon/Invoke-Obfuscation">danielbohannon/Invoke-Obfuscation</a></td>
        <td>Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator</td>
    </tr>
    <tr>
        <td><a href="https://github.com/DanMcInerney/icebreaker">DanMcInerney/icebreaker</a></td>
        <td>Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment</td>
    </tr>
    <tr>
        <td><a href="https://github.com/DefensiveOrigins/PlumHound">DefensiveOrigins/PlumHound</a></td>
        <td>Bloodhound for Blue and Purple Teams</td>
    </tr>
    <tr>
        <td><a href="https://github.com/eladshamir/Internal-Monologue">eladshamir/Internal-Monologue</a></td>
        <td>Internal Monologue Attack: Retrieving NTLM Hashes without Touching LSASS</td>
    </tr>
    <tr>
        <td><a href="https://github.com/FSecureLABS/physmem2profit">FSecureLABS/physmem2profit </a></td>
        <td>Physmem2profit can be used to create a minidump of a target hosts' LSASS process by analysing physical memory remotely</td>
    </tr>
    <tr>
        <td><a href="https://github.com/fbkcs/ThunderDNS">fbkcs/ThunderDNS</a></td>
        <td>This tool can forward TCP traffic over DNS protocol. Non-compile clients + socks5 support.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/fireeye/SharPersist">fireeye/SharPersist</a></td>
        <td>Windows persistence toolkit written in C#.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/FuzzySecurity/PowerShell-Suite">FuzzySecurity/PowerShell-Suite</a></td>
        <td>There are great tools and resources online to accomplish most any task in PowerShell, sometimes however, there is a need to script together a util for a specific purpose or to bridge an ontological gap. This is a collection of PowerShell utilities I put together either for fun or because I had a narrow application in mind.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/FuzzySecurity/Sharp-Suite">FuzzySecurity/Sharp-Suite</a></td>
        <td>My musings with C#</td>
    </tr>
    <tr>
        <td><a href="https://github.com/GhostPack/Seatbelt">GhostPack/Seatbelt</a></td>
        <td>Seatbelt is a C# project that performs a number of security oriented host-survey "safety checks" relevant from both offensive and defensive security perspectives.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/google/sandbox-attacksurface-analysis-tools">google/sandbox-attacksurface-analysis-tools</a></td>
        <td>This is a small suite of tools to test various properties of sandboxes on Windows. Many of the checking tools take a -p flag which is used to specify the PID of a sandboxed process. The tool will impersonate the token of that process and determine what access is allowed from that location. Also it's recommended to run these tools as an administrator or local system to ensure the system can be appropriately enumerated.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/hlldz/dazzleUP">hlldz/dazzleUP</a></td>
        <td>A tool that detects the privilege escalation vulnerabilities caused by misconfigurations and missing updates in the Windows operating systems.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/hlldz/Invoke-Phant0m">hlldz/Invoke-Phant0m</a></td>
        <td>Windows Event Log Killer</td>
    </tr>
    <tr>
        <td><a href="https://github.com/huntresslabs/evading-autoruns">huntresslabs/evading-autoruns</a></td>
        <td>Slides and reference material from Evading Autoruns presentation at DerbyCon 7 (September 2017)</td>
    </tr>
    <tr>
        <td><a href="https://github.com/JohnLaTwC/PyPowerShellXray">JohnLaTwC/PyPowerShellXray</a></td>
        <td>Python script to decode common encoded PowerShell scripts</td>
    </tr>
    <tr>
        <td><a href="https://github.com/jonatan1024/clrinject">jonatan1024/clrinject</a></td>
        <td>Injects C# EXE or DLL Assembly into every CLR runtime and AppDomain of another process.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Kevin-Robertson/Inveigh">Kevin-Robertson/Inveigh</td>
        <td>Windows PowerShell ADIDNS/LLMNR/mDNS/NBNS spoofer/man-in-the-middle tool</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mattifestation/PoCSubjectInterfacePackage">mattifestation/PoCSubjectInterfacePackage</a></td>
        <td>A PoC subject interface package (SIP) provider designed to educate about the required components of a SIP provider.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mdsecactivebreach/Chameleon">mdsecactivebreach/Chameleon</a></td>
        <td>Chameleon: A tool for evading Proxy categorisation</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mdsecactivebreach/SharpShooter">mdsecactivebreach/SharpShooter</a></td>
        <td>SharpShooter is a payload creation framework for the retrieval and execution of arbitrary CSharp source code.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/monoxgas/sRDI">monoxgas/sRDI</a></td>
        <td>Shellcode implementation of Reflective DLL Injection. Convert DLLs to position independent shellcode</td>
    </tr>
    <tr>
        <td><a href="https://github.com/nccgroup/demiguise">nccgroup/demiguise</a></td>
        <td>HTA encryption tool for RedTeams</td>
    </tr>
    <tr>
        <td><a href="https://github.com/nccgroup/GTFOBLookup">nccgroup/GTFOBLookup</a></td>
        <td>Offline command line lookup utility for GTFOBins</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Ne0nd0g/merlin">Ne0nd0g/merlin</a></td>
        <td>Merlin is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in golang.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/NetSPI/ESC">NetSPI/ESC</a></td>
        <td>Evil SQL Client (ESC) is an interactive .NET SQL console client with enhanced SQL Server discovery, access, and data exfiltration features. While ESC can be a handy SQL Client for daily tasks, it was originally designed for targeting Active Directory domain joined SQL Servers during penetration tests and red team engagements.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/NetSPI/goddi">NetSPI/goddi</a></td>
        <td>goddi (go dump domain info) dumps Active Directory domain information</td>
    </tr>
    <tr>
        <td><a href="https://github.com/nidem/kerberoast">nidem/kerberoast</a></td>
        <td>Kerberoast is a series of tools for attacking MS Kerberos implementations. Below is a brief overview of what each tool does.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/outflanknl/Recon-AD">outflanknl/Recon-AD</a></td>
        <td>Recon-AD, an AD recon tool based on ADSI and reflective DLL’s</td>
    </tr>
    <tr>
        <td><a href="https://github.com/OmerYa/Invisi-Shell">OmerYa/Invisi-Shell</a></td>
        <td>Hide your Powershell script in plain sight. Bypass all Powershell security features</td>
    </tr>
    <tr>
        <td><a href="https://github.com/peewpw/Invoke-PSImage">peewpw/Invoke-PSImage</a></td>
        <td>Embeds a PowerShell script in the pixels of a PNG file and generates a oneliner to execute</td>
    </tr>
    <tr>
        <td><a href="https://github.com/peewpw/Invoke-WCMDump">peewpw/Invoke-WCMDump</a></td>
        <td>PowerShell Script to Dump Windows Credentials from the Credential Manager</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Plazmaz/LNKUp">Plazmaz/LNKUp</a></td>
        <td>Generates malicious LNK file payloads for data exfiltration</td>
    </tr>
    <tr>
        <td><a href="http://prismatica.io/">Project Prismatica</a></td>
        <td>Project Prismatica is a focused framework for Command and Control that is dedicated to extensibility.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/putterpanda/mimikittenz">putterpanda/mimikittenz</a></td>
        <td>A post-exploitation powershell tool for extracting juicy info from memory.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/secretsquirrel/SigThief">secretsquirrel/SigThief</a></td>
        <td>Stealing Signatures and Making One Invalid Signature at a Time</td>
    </tr>
    <tr>
        <td><a href="https://github.com/sensepost/godoh">sensepost/goDoH</a></td>
        <td>godoh - A DNS-over-HTTPS C2</td>
    </tr>
    <tr>
        <td><a href="https://github.com/sevagas/macro_pack">sevagas/macro_pack</a></td>
        <td>macro_pack is a tool used to automatize obfuscation and generation of MS Office documents for pentest, demo, and social engineering assessments. The goal of macro_pack is to simplify antimalware bypass and automatize the process from vba generation to final Office document generation.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/shellster/DCSYNCMonitor">shellster/DCSYNCMonitor</a></td>
        <td>Monitors for DCSYNC and DCSHADOW attacks and create custom Windows Events for these events.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/SpiderLabs/DoHC2">SpiderLabs/DoHC2</a></td>
        <td>DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH).</td>
    </tr>
    <tr>
        <td><a href="https://github.com/stephenfewer/ReflectiveDLLInjection">stephenfewer/ReflectiveDLLInjection</a></td>
        <td>Reflective DLL injection is a library injection technique in which the concept of reflective programming is employed to perform the loading of a library from memory into a host process</td>
    </tr>
    <tr>
        <td><a href="https://github.com/sud0woodo/DCOMrade">sud0woodo/DCOMrade</a></td>
        <td>Powershell script for enumerating vulnerable DCOM Applications</td>
    </tr>
    <tr>
        <td><a href="https://github.com/slyd0g/UrbanBishopLocal">slyd0g/UrbanBishopLocal</a></td>
        <td>A port of FuzzySecurity's UrbanBishop project for inline shellcode execution. The execution vector uses a delegate vs an APC on a suspended threat at ntdll!RtlExitUserThread in UrbanBishop</td>
    </tr>
    <tr>
        <td><a href="https://github.com/TheSecondSun/Bashark">TheSecondSun/Bashark</a></td>
        <td>Bash post exploitation toolkit</td>
    </tr>
    <tr>
        <td><a href="https//github.com/trustedsec/unicorn">trustedsec/unicorn</a></td>
        <td>Unicorn is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory. Based on Matthew Graeber's powershell attacks and the powershell bypass technique presented by David Kennedy (TrustedSec) and Josh Kelly at Defcon 18.</td>
    </tr>
</table>

## Social Engineering

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/AlteredSecurity/365-Stealer/">AlteredSecurity/365-Stealer/</a></td>
        <td>365-Stealer is the tool written in python3 which steals data from victims office365 by using access_token which we get by phishing. It steals outlook mails, attachments, OneDrive files, OneNote notes and injects macros.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/boxug/trape">boxug/trape</a></td>
        <td>People tracker on the Internet: Learn to track the world, to avoid being traced.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/dafthack/MailSniper">dafthack/MailSniper</a></td>
        <td>MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords, insider intel, network architecture information, etc.). It can be used as a non-administrative user to search their own email, or by an administrator to search the mailboxes of every user in a domain.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/drk1wi/Modlishka">drk1wi/Modlishka</a></td>
        <td>Modlishka. Reverse Proxy. Phishing NG.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/certsocietegenerale/swordphish-awareness">certsocietegenerale/swordphish-awareness</a></td>
        <td>Swordphish is a plateform allowing to create and manage fake phishing campaigns.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/curtbraz/Phishing-API">curtbraz/Phishing-API</a></td>
        <td>Comprehensive Web Based Phishing Suite of Tools for Rapid Deployment and Real-Time Alerting!</td>
    </tr>
	<tr>
		<td><a href="https://emailrep.io/">Simple Email Reputation</a></td>
		<td>Illuminate the "reputation" behind an email address</td>
	</tr>
    <tr>
        <td><a href="https://github.com/fireeye/ReelPhish">fireeye/ReelPhish</a></td>
        <td>ReelPhish: A Real-Time Two-Factor Phishing Tool</td>
    </tr>
    <tr>
        <td><a href="https://github.com/gophish/gophish">gophish/gophish</a></td>
        <td>Gophish is an open-source phishing toolkit designed for businesses and penetration testers. It provides the ability to quickly and easily setup and execute phishing engagements and security awareness training</td>
    </tr>
    <tr>
        <td><a href="https://github.com/kgretzky/evilginx2">kgretzky/evilginx2</a></td>
        <td>Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies, allowing for the bypass of 2-factor authentication</td>
    </tr>
    <tr>
        <td><a href="https://www.mailsploit.com/index">Mailsploit</a></td>
        <td>TL;DR: Mailsploit is a collection of bugs in email clients that allow effective sender spoofing and code injection attacks. The spoofing is not detected by Mail Transfer Agents (MTA) aka email servers, therefore circumventing spoofing protection mechanisms such as DMARC (DKIM/SPF) or spam filters.</td>
    </tr>
	<tr>
		<td><a href="https://github.com/mdsecactivebreach/o365-attack-toolkit">mdsecactivebreach/o365-attack-toolkit</a></td>
		<td>o365-attack-toolkit allows operators to perform an OAuth phishing attack and later on use the Microsoft Graph API to extract interesting information.</td>
	</tr>
	<tr>
		<td><a href="https://github.com/muraenateam/muraena">muraenateam/muraena</a></td>
		<td>Muraena is an almost-transparent reverse proxy aimed at automating phishing and post-phishing activities.</td>
	</tr>
    <tr>
        <td><a href="https://github.com/Raikia/UhOh365">Raikia/UhOh365</a></td>
        <td> A script that can see if an email address is valid in Office365 (user/email enumeration). This does not perform any login attempts, is unthrottled, and is incredibly useful for social engineering assessments to find which emails exist and which don't. </td>
    </tr>
    <tr>
        <td><a href="https://github.com/ring0lab/catphish">ring0lab/catphish</a></td>
        <td>Generate similar-looking domains for phishing attacks. Check expired domains and their categorized domain status to evade proxy categorization. Whitelisted domains are perfect for your C2 servers.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/securestate/king-phisher/">securestate/king-phisher</a></td>
        <td>Phishing Campaign Toolkit</td>
    </tr>
    <tr>
        <td><a href="https://github.com/thelinuxchoice/blackeye">thelinuxchoice/blackeye</a></td>
        <td>The most complete Phishing Tool, with 32 templates +1 customizable</td>
    </tr>
    <tr>
        <td><a href="https://github.com/thelinuxchoice/shellphish">thelinuxchoice/shellphish</a></td>
        <td>Phishing Tool for 18 social media: Instagram, Facebook, Snapchat, Github, Twitter, Yahoo, Protonmail, Spotify, Netflix, Linkedin, Wordpress, Origin, Steam, Microsoft, InstaFollowers, Gitlab, Pinterest</td>
    </tr>
    <tr>
        <td><a href="https://github.com/UndeadSec/EvilURL">Undeadsec/EvilURL</a></td>
        <td>An unicode domain phishing generator for IDN Homograph Attack</td>
    </tr>
    <tr>
        <td><a href="https://github.com/UndeadSec/SocialFish">UndeadSec/SocialFish</a></td>
        <td>Ultimate phishing tool. Socialize with the credentials</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ustayready/CredSniper">ustayready/CredSniper</a></td>
        <td>CredSniper is a phishing framework written with the Python micro-framework Flask and Jinja2 templating which supports capturing 2FA tokens.</td>
    </tr>
</table>

## Vulnerable

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/appsecco/VyAPI">appsecco/VyAPI</a></td>
        <td>VyAPI - A cloud based vulnerable hybrid Android App</a></td>
    </tr>
	<tr>
		<td><a href="https://github.com/AutomatedLab/AutomatedLab">AutomatedLab/AutomatedLab</a></td>
		<td>AutomatedLab is a provisioning solution and framework that lets you deploy complex labs on HyperV and Azure with simple PowerShell scripts. It supports all Windows operating systems from 2008 R2 to 2016 including Nano Server and various products like AD, Exchange, PKI, IIS, etc.</td>
	</tr>
    <tr>
        <td><a href="https://github.com/avishayil/caponeme">avishayil/caponeme</a></td>
        <td>Repository demonstrating the Capital One breach on your AWS account</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Azure/Convex">Azure/Convex</a></td>
        <td>Cloud Open-source Network Vulnerability Exploitation eXperience (CONVEX) spins up Capture The Flag environments in your Azure tenant for participants to play through.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Billy-Ellis/Exploit-Challenges">Billy-Ellis/Exploit-Challenges</a></td>
        <td>A collection of vulnerable ARM binaries for practicing exploit development</td>
    </tr>
    <tr>
        <td><a href="https://github.com/bkerler/exploit_me">bkerler/exploit_me</a></td>
        <td>Very vulnerable ARM application (CTF style exploitation tutorial)</td>
    </tr>
    <tr>
        <td><a href="https://github.com/bkimminich/juice-shop">bkimminich/juice-shop</a></td>
        <td>OWASP Juice Shop is an intentionally insecure webapp for security trainings written entirely in Javascript which encompasses the entire OWASP Top Ten and other severe security flaws.</td>
    </tr>
    <tr>
		<td><a href="https://github.com/bridgecrewio/terragoat">bridgecrewio/terragoat</a></td>
		<td>TerraGoat is Bridgecrew's "Vulnerable by Design" Terraform repository. TerraGoat is a learning and training project that demonstrates how common configuration errors can find their way into production cloud environments.</td>
	</tr>
    <tr>
        <td><a href="https://github.com/clong/DetectionLab">clong/DetectionLab</a></td>
        <td>Vagrant & Packer scripts to build a lab environment complete with security tooling and logging best practices</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cliffe/SecGen">cliffe/SecGen</a></td>
        <td>SecGen creates vulnerable virtual machines so students can learn security penetration testing techniques.</td>
    </tr>
    <tr>
        <td><a href="https://tuts4you.com/download.php?list.17">Lenas Reversing for Newbies</a></td>
        <td>Nice collection of tutorials aimed particularly for newbie reverse enginners...</td>
    </tr>
    <tr>
        <td><a href="https://github.com/google/google-ctf">google/google-ctf</a></td>
        <td>This repository lists most of the challenges used in the Google CTF 2017. The missing challenges are not ready to be open-sourced, or contain third-party code.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/nccgroup/sadcloud">nccgroup/sadcloud</a></td>
        <td>A tool for standing up (and tearing down!) purposefully insecure cloud infrastructure</td>
    </tr>
    <tr>
        <td><a href="https://github.com/OWASP/iGoat-Swift">OWASP/iGoat-Swift</a></td>
        <td>OWASP iGoat (Swift) - A Damn Vulnerable Swift Application for iOS</td>
    </tr>
    <tr>
        <td><a href="https://github.com/rapid7/hackazon">rapid7/hackazon</a></td>
        <td>A modern vulnerable web app</td>
    </tr>
    <tr>
        <td><a href="https://martin.uy/blog/projects/reverse-engineering/">Reverse Engineering</a></td>
        <td>Welcome to the Reverse Engineering open course! This course is a journey into executable binaries and operating systems from 3 different angles: 1) Malware analysis, 2) Bug hunting and 3) Exploit writing. Both  Windows and Linux x86/x86_64 platforms are under scope.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/sagishahar/lpeworkshop">sagishahar/lpeworkshop</a></td>
        <td>Windows / Linux Local Privilege Escalation Workshop</td>
    </tr>
    <tr>
        <td><a href="http://www.cis.syr.edu/~wedu/seed/labs.html">SEED Labs</a></td>
        <td>Various labs from SEED Project</td>
    </tr>
    <tr>
        <td><a href="https://www.notsosecure.com/vulnerable-docker-vm/">Vulnerable Docker VM</a></td>
        <td>Ever fantasized about playing with docker misconfigurations, privilege escalation, etc. within a container?</td>
    </tr>
</table>
