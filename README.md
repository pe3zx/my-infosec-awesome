# My Infosec Awesome <!-- omit in toc -->

<p align="center">
  <img src="cover.png">
</p>

<p align="center"><img src="https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg" /> <img src="https://img.shields.io/github/last-commit/pe3zx/my-infosec-awesome.svg"/> </p>

---

**Update Nov 18, 2020**: [Offensive Bookmark.md](Offensive.md) has been created based on my need to map bookmarks (and tools) that practice tactics and techniques for offensive operations with MITRE ATT&CK Enterprise Matrix. The Post Exploitation section on [README.md](readme.md) is now migrate to the new page. I will update the new page with my personal bookmark soon.

---

This repository is created as an online bookmark for useful links, resources and tools in infosec field which serve my needs to have a searchable page to look further.

- [Adversary Simulation & Emulation](#adversary-simulation--emulation)
- [Application Security](#application-security)
- [Binary Analysis](#binary-analysis)
- [Cloud Security](#cloud-security)
- [Courses](#courses)
- [Cryptography](#cryptography)
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
- [Social Engineering](#social-engineering)
- [Smart Contract](#smart-contract)
- [Vulnerable](#vulnerable)

## Adversary Simulation & Emulation

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/activeshadow/go-atomicredteam">activeshadow/go-atomicredteam</a></td>
        <td>go-atomicredteam is a Golang application to execute tests as defined in the atomics folder of Red Canary's Atomic Red Team project</td>
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
        <td><a href="https://github.com/Azure/Cloud-Katana">Azure/Cloud-Katana</a></td>
        <td>Unlocking Serverless Computing to Assess Security Controls</td>
    </tr>
    <tr>
        <td><a href="https://github.com/BinaryDefense/beacon-fronting">BinaryDefense/beacon-fronting</a></td>
        <td>A simple command line program to help defender test their detections for network beacon patterns and domain fronting</td>
    </tr>
    <tr>
        <td><a href="https://github.com/blackbotinc/Atomic-Red-Team-Intelligence-C2">blackbotinc/Atomic-Red-Team-Intelligence-C2</a></td>
        <td>ARTi-C2 is a post-exploitation framework used to execute Atomic Red Team test cases with rapid payload deployment and execution capabilities via .NET's DLR.</td>
    </tr>
    <tr>
        <td><a href="https://www.encripto.no/en/downloads-2/tools/">Blue Team Training Toolkit</a></td>
        <td>Blue Team Training Toolkit (BT3) is designed for network analysis training sessions, incident response drills and red team engagements</td>
    </tr>
    <tr>
        <td><a href="https://github.com/carbonblack/excel4-tests">carbonblack/excel4-tests</a></td>
        <td>Carbon Black TAU Excel 4 Macro Analysis</td>
    </tr>
    <tr>
        <td><a href="https://github.com/center-for-threat-informed-defense/adversary_emulation_library">center-for-threat-informed-defense/adversary_emulation_library</a></td>
        <td>An open library of adversary emulation plans designed to empower organizations to test their defenses based on real-world TTPs.</td>
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
        <td><a href="https://github.com/Datadog/stratus-red-team/">Datadog/stratus-red-team</a></td>
        <td>☁️ ⚡ Granular, Actionable Adversary Emulation for the Cloud.</td>
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
        <td><a href="https://github.com/FourCoreLabs/firedrill">FourCoreLabs/firedrill</a></td>
        <td>firedrill is a malware simulation harness for evaluating your security controls</td>
    </tr>
    <tr>
        <td><a href="https://github.com/fozavci/tehsat">fozavci/tehsat</a></td>
        <td>Tehsat Malware Traffic Generator</td>
    </tr>
   <tr>
        <td><a href="https://github.com/FSecureLABS/leonidas">FSecureLABS/leonidas</a></td>
        <td>Automated Attack Simulation in the Cloud, complete with detection use cases.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/JonathanSalwan/Triton">JonathanSalwan/Triton</a></td>
        <td>Triton is a dynamic binary analysis library. Build your own program analysis tools, automate your reverse engineering, perform software verification or just emulate code.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/jymcheong/AutoTTP">jymchoeng/AutoTTP</a></td>
        <td>Automated Tactics Techniques & Procedures</td>
    </tr>
    <tr>
        <td><a href="https://github.com/lawrenceamer/0xsp-Mongoose">lawrenceamer/0xsp-Mongoose</a></td>
        <td>a unique framework for cybersecurity simulation and red teaming operations, windows auditing for newer vulnerabilities, misconfigurations and privilege escalations attacks, replicate the tactics and techniques of an advanced adversary in a network.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/microsoft/restler-fuzzer">microsoft/restler-fuzzer</a></td>
        <td>RESTler is the first stateful REST API fuzzing tool for automatically testing cloud services through their REST APIs and finding security and reliability bugs in these services.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/MiladMSFT/ThreatHunt">MiladMSFT/ThreatHunt</a></td>
        <td>ThreatHunt is a PowerShell repository that allows you to train your threat hunting skills.</td>
    </tr>
   <tr>
        <td><a href="https://github.com/mitre/caldera">mitre/caldera</a></td>
        <td>An automated adversary emulation system</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mvelazc0/PurpleSharp">mvelazc0/PurpleSharp</a></td>
        <td>PurpleSharp is a C# adversary simulation tool that executes adversary techniques with the purpose of generating attack telemetry in monitored Windows environments</td>
    </tr>
    <tr>
        <td><a href="https://github.com/NextronSystems/APTSimulator">NextronSystems/APTSimulator</a></td>
        <td>A toolset to make a system look as if it was the victim of an APT attack</td>
    </tr>
    <tr>
        <td><a href="https://github.com/NextronSystems/ransomware-simulator">NextronSystems/ransomware-simulator</a></td>
        <td>Ransomware simulator written in Golang</td>
    </tr>
    <tr>
        <td><a href="https://github.com/n0dec/MalwLess">n0dec/MalwLess</a></td>
        <td>Test blue team detections without running any attack</td>
    </tr>
    <tr>
        <td><a href="https://github.com/OTRF/Microsoft-Sentinel2Go">OTRF/Microsoft-Sentinel2Go</a></td>
        <td>Microsoft Sentinel2Go is an open source project developed to expedite the deployment of a Microsoft Sentinel research lab.</td>
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
        <td><a href="https://github.com/qsecure-labs/overlord">qsecure-labs/overlord</a></td>
        <td>Overlord - Red Teaming Infrastructure Automation</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ReconInfoSec/adversary-emulation-map">ReconInfoSec/adversary-emulation-map</a></td>
        <td>Creates an ATT&CK Navigator map of an Adversary Emulation Plan</td>
    </tr>
    <tr>
        <td><a href="https://github.com/redcanaryco/atomic-red-team">redcanaryco/atomic-red-team</a></td>
        <td>Small and highly portable detection tests based on MITRE's ATT&CK.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/redcanaryco/AtomicTestHarnesses">redcanaryco/AtomicTestHarnesses</a></td>
        <td>Public Repo for Atomic Test Harness</td>
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
        <td><a href="https://github.com/RedTeamOperations/RedCloud-OS">RedTeamOperations/RedCloud-OS</a></td>
        <td>RedCloudOS is a Cloud Adversary Simulation Operating System for Red Teams to assess the Cloud Security of Leading Cloud Service Providers (CSPs)</td>
    </tr>
    <tr>
        <td><a href="https://github.com/nickzer0/RedLab">nickzer0/RedLab</a></td>
        <td>Files for red team lab infrastructure.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ScarredMonk/SysmonSimulator">ScarredMonk/SysmonSimulator</a></td>
        <td>Sysmon event simulation utility which can be used to simulate the attacks to generate the Sysmon Event logs for testing the EDR detections and correlation rules by Blue teams.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/SecurityRiskAdvisors/VECTR">SecurityRiskAdvisors/VECTR</a></td>
        <td>VECTR is a tool that facilitates tracking of your red and blue team testing activities to measure detection and prevention capabilities across different attack scenarios</td>
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
        <td><a href="https://github.com/splunk/salo">splunk/salo</a></td>
        <td>Synthetic Adversarial Log Objects: A Framework for synthentic log generation</td>
    </tr>
    <tr>
        <td><a href="https://bots.splunk.com/login?redirect=/">Splunk Boss of SOC</a></td>
        <td>Splunk Boss of SOC</td>
    </tr>
    <tr>
        <td><a href="https://github.com/swimlane/atomic-operator">swimlane/atomic-operator</a></td>
        <td>A Python package is used to execute Atomic Red Team tests (Atomics) across multiple operating system environments.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/swimlane/soc-faker">swimlane/soc-faker</a></td>
        <td>A python package for use in generating fake data for SOC and security automation.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/TryCatchHCF/DumpsterFire">TryCatchHCF/DumpsterFire</a></td>
        <td>"Security Incidents In A Box!" A modular, menu-driven, cross-platform tool for building customized, time-delayed, distributed security events.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/uber-common/metta">uber-common/metta</a></td>
        <td>An information security preparedness tool to do adversarial simulation.</td>
    </tr>
    <tr>
        <td><a href="https://mitre.github.io/unfetter/">Unfetter</a></td>
        <td>Unfetter is a project designed to help network defenders, cyber security professionals, and decision makers identify and analyze defensive gaps in a more scalable and repeatable way</td>
    </tr>
    <tr>
        <td><a href="https://github.com/warhorse/warhorse">warhorse/warhorse</a></td>
        <td>Warhorse consists of a fully-featured Ansible playbook to deploy infrastructure in the cloud for conducting security assessments.</td>
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
        <td><a href="https://github.com/aquasecurity/kube-hunter">aquasecurity/kube-hunter</a></td>
        <td>Hunt for security weaknesses in Kubernetes clusters</td>
    </tr>
    <tr>
        <td><a href="https://github.com/aquasecurity/trivy">aquasecurity/trivy</a></td>
        <td>A Simple and Comprehensive Vulnerability Scanner for Container Images, Git Repositories and Filesystems. Suitable for CI</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ARPSyndicate/kenzer">ARPSyndicate/kenzer</a></td>
        <td>automated web assets enumeration & scanning</td>
    </tr>
    <tr>
        <td><a href="https://developers.google.com/assured-oss">Assured OSS</a></td>
        <td>Improve the security of your software supply chain by incorporating the same trusted open source software (OSS) packages that Google secures and uses into your own developer workflows.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/barrracud4/image-upload-exploits">barrracud4/image-upload-exploits</a></td>
        <td>This repository contains various media files for known attacks on web applications processing media files. Useful for penetration tests and bug bounty.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/BishopFox/GitGot">BishopFox/GitGot</a></td>
        <td>Semi-automated, feedback-driven tool to rapidly search through troves of public data on GitHub for sensitive secrets.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/BishopFox/h2csmuggler">BishopFox/h2csmuggler</a></td>
        <td>HTTP Request Smuggling over HTTP/2 Cleartext (h2c)</td>
    </tr>
    <tr>
        <td><a href="https://github.com/brannondorsey/dns-rebind-toolkit">brannondorsey/dns-rebind-toolkit</a></td>
        <td>A front-end JavaScript toolkit for creating DNS rebinding attacks.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/bridgecrewio/checkov">bridgecrewio/checkov</a></td>
        <td>Prevent cloud misconfigurations during build-time for Terraform, Cloudformation, Kubernetes, Serverless framework and other infrastructure-as-code-languages with Checkov by Bridgecrew.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/brompwnie/botb">brompwnie/botb</a></td>
        <td>A container analysis and exploitation tool for pentesters and engineers.</td>
    </tr>
    <tr>
        <td><a href="https://bugbountyrecon.com/">Bug Bounty Recon</a></td>
        <td>Bug Bounty Recon (bbrecon) is a Recon-as-a-Service for bug bounty hunters and security researchers. The API aims to provide a continuously up-to-date map of the Internet "safe harbor" attack surface, excluding out-of-scope targets.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Checkmarx/kics">Checkmarx/kics</a></td>
        <td>Find security vulnerabilities, compliance issues, and infrastructure misconfigurations early in the development cycle of your infrastructure-as-code with KICS by Checkmarx.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/chvancooten/BugBountyScanner">chvancooten/BugBountyScanner</a></td>
        <td>A Bash script and Docker image for Bug Bounty reconnaissance. Intended for headless use.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/danmar/cppcheck">danmar/cppcheck</a></td>
        <td>static analysis of C/C++ code</td>
    </tr>
    <tr>
        <td><a href="https://github.com/deepfence/SecretScanner">deepfence/SecretScanner</a></td>
        <td>Find secrets and passwords in container images and file systems</td>
    </tr>
    <tr>
        <td><a href="https://github.com/deepfence/ThreatMapper">deepfence/ThreatMapper</a></td>
        <td>Identify vulnerabilities in running containers, images, hosts and repositories</td>
    </tr>
    <tr>
        <td><a href="https://github.com/DefectDojo/django-DefectDojo">DefectDojo/django-DefectDojo</a></td>
        <td>DefectDojo is an open-source application vulnerability correlation and security orchestration tool.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/delvelabs/tachyon">delvelabs/tachyon</a></td>
        <td>Tachyon is a fast web application security reconnaissance tool.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/delvelabs/vane2">delvelabs/vane2</a></td>
        <td>WordPress version identification and vulnerability finder.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/doyensec/inql">doyensec/inql</a></td>
        <td>InQL - A Burp Extension for GraphQL Security Testing</td>
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
        <td><a href="https://github.com/Findomain/Findomain">Findomain/Findomain</a></td>
        <td>The fastest and cross-platform subdomain enumerator, do not waste your time.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/fkie-cad/cwe_checker">fkie-cad/cwe_checker</a></td>
        <td>cwe_checker finds vulnerable patterns in binary executables</td>
    </tr>
    <tr>
        <td><a href="https://github.com/google/atheris">google/atheris</a></td>
        <td>Atheris is a coverage-guided Python fuzzing engine. It supports fuzzing of Python code, but also native extensions written for CPython. Atheris is based off of libFuzzer. When fuzzing native code, Atheris can be used in combination with Address Sanitizer or Undefined Behavior Sanitizer to catch extra bugs.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/google/tsunami-security-scanner">google/tsunami-security-scanner</a></td>
        <td>Tsunami is a general purpose network security scanner with an extensible plugin system for detecting high severity vulnerabilities with high confidence.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/googleprojectzero/weggli">googleprojectzero/weggli</a></td>
        <td>weggli is a fast and robust semantic search tool for C and C++ codebases. It is designed to help security researchers identify interesting functionality in large codebases.</td>
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
        <td><a href="https://github.com/LanikSJ/dfimage">LanikSJ/dfimage</a></td>
        <td>Reverse-engineer a Dockerfile from a Docker image.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/lelinhtinh/de4js">lelinhtinh/de4js</a></td>
        <td>JavaScript Deobfuscator and Unpacker</td>
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
        <td><a href="https://github.com/nccgroup/singularity">nccgroup/singularity</a></td>
        <td>A DNS rebinding attack framework</td>
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
        <td><a href="https://github.com/NotSoSecure/SerializedPayloadGenerator">NotSoSecure/SerializedPayloadGenerator</a></td>
        <td>It's Web Interface to generate payload using various deserialization exploitation framework</td>
    </tr>
    <tr>
        <td><a href="https://github.com/noqcks/xeol">noqcks/xeol</a></td>
        <td>Xeol is a scanner for End Of Life (EOL) packages in container images, systems, and SBOMs</td>
    </tr>
    <tr>
        <td><a href="https://deps.dev/">  Insights</a></td>
        <td>Open Source Insights is an experimental service developed and hosted by Google to help developers better understand the structure, construction, and security of open source software packages.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ossf/allstar">ossf/allstar</a></td>
        <td>GitHub App to set and enforce security policies</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ossf/scorecard">ossf/scorecard</a></td>
        <td>Security Scorecards - Security health metrics for Open Source</td>
    </tr>
    <tr>
        <td><a href="https://github.com/OJ/gobuster">OJ/gobuster</a></td>
        <td>Directory/File, DNS and VHost busting tool written in Go</td>
    </tr>
    <tr>
        <td><a href="https://github.com/OWASP/Nettacker">OWASP/Nettacker</a></td>
        <td>Automated Penetration Testing Framework - Open-Source Vulnerability Scanner - Vulnerability Management</td>
    </tr>
    <tr>
        <td><a href="https://github.com/OWASP/wstg">OWASP/wstg</a></td>
        <td>The Web Security Testing Guide is a comprehensive Open Source guide to testing the security of web applications and web services.</td>
    </tr>
    <tr>
        <td><a href="https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project">OWASP Zed Attack Proxy Project</a></td>
        <td>The OWASP Zed Attack Proxy (ZAP) is one of the world’s most popular free security tools and is actively maintained by hundreds of international volunteers</td>
    </tr>
    <tr>
        <td><a href="https://github.com/PerimeterX/Restringer">PerimeterX/Restringer</a></td>
        <td>A Javascript Deobfuscator</td>
    </tr>
    <tr>
        <td><a href="https://github.com/praetorian-inc/gokart">praetorian-inc/gokart</a></td>
        <td>A static analysis tool for securing Go code</td>
    </tr>
    <tr>
        <td><a href="https://github.com/praetorian-inc/snowcat">praetorian-inc/snowcat</a></td>
        <td>a tool to audit the istio service mesh</td>
    </tr>
    <tr>
        <td><a href="https://github.com/pimps/JNDI-Exploit-kit">pimps/JNDI-Exploit-kit</a></td>
        <td>JNDI-Exploitation-Kit（A modified version of the great JNDI-Injection-Exploit created by @welk1n. This tool can be used to start an HTTP Server, RMI Server and LDAP Server to exploit java web apps vulnerable to JNDI Injection</td>
    </tr>
    <tr>
        <td><a href="https://github.com/presidentbeef/brakeman">presidentbeef/brakeman</a></td>
        <td>A static analysis security vulnerability scanner for Ruby on Rails applications</td>
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
        <td><a href="https://github.com/quarkslab/kdigger">quarkslab/kdigger</a></td>
        <td>kdigger is a context discovery tool for Kubernetes penetration testing.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/redphx/localify">redphx/localify</a></td>
        <td>Effectively debug minified JS files</td>
    </tr>
    <tr>
        <td><a href="https://github.com/RedTeamPentesting/monsoon">RedTeamPentesting/monsoon</a></td>
        <td>Fast HTTP enumerator</td>
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
        <td><a href="https://github.com/rpgeeganage/audit-node-modules-with-yara">rpgeeganage/audit-node-modules-with-yara</a></td>
        <td>Audit Node Module folder with YARA rules to identify possible malicious packages hiding in node_moudles</td>
    </tr>
     <tr>
        <td><a href="https://github.com/s0md3v/XSStrike">s0md3v/XSStrike</a></td>
        <td>Most advanced XSS detection suite</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Screetsec/Sudomy">Screetsec/Sudomy</a></td>
        <td>Sudomy is a subdomain enumeration tool to collect subdomains and analyzing domains performing automated reconnaissance (recon) for bug hunting / pentesting</td>
    </tr>
    <tr>
        <td><a href="https://github.com/securego/gosec">securego/gosec</a></td>
        <td>Golang security checker</td>
    </tr>
    <tr>
        <td><a href="https://slsa.dev/">SLSA</a></td>
        <td>Safeguarding artifact integrity across any software supply chain</td>
    </tr>
    <tr>
        <td><a href="https://snyk.io/">Snyk</a></td>
        <td>Continuously find & fix vulnerabilities in your dependencies</td>
    </tr>
    <tr>
        <td><a href="https://github.com/sslab-gatech/Rudra">sslab-gatech/Rudra</a></td>
        <td>Rust Memory Safety & Undefined Behavior Detection</td>
    </tr>
   <tr>
        <td><a href="https://github.com/subfinder/subfinder">subfinder/subfinder</a></td>
        <td>SubFinder is a subdomain discovery tool that discovers valid subdomains for websites. Designed as a passive framework to be useful for bug bounties and safe for penetration testing.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/target/mmk-ui-api">target/mmk-ui-api</a></td>
        <td>UI, API, and Scanner (Rules Engine) services for Merry Maker</td>
    </tr>
    <tr>
        <td><a href="https://github.com/trailofbits/it-depends">trailofbits/it-depends</a></td>
        <td>A tool to automatically build a dependency graph and Software Bill of Materials (SBOM) for packages and arbitrary source code repositories.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/vchinnipilli/kubestriker">vchinnipilli/kubestriker</a></td>
        <td>A Blazing fast Security Auditing tool for Kubernetes</td>
    </tr>
    <tr>
        <td><a href="https//github.com/visma-prodsec/confused">visma-prodsec/confused</a></td>
        <td>Tool to check for dependency confusion vulnerabilities in multiple package management systems</td>
    </tr>
    <tr>
        <td><a href="https://github.com/wallarm/gotestwaf">wallarm/gotestwaf</a></td>
        <td>Go Test WAF project, a tool to test different WAF detects for apps and APIs</td>
    </tr>
    <tr>
        <td><a href="https://github.com/wagiro/BurpBounty">wagiro/BurpBounty</a></td>
        <td>Burp Bounty (Scan Check Builder in BApp Store) is a extension of Burp Suite that allows you, in a quick and simple way, to improve the active and passive scanner by means of personalized rules through a very intuitive graphical interface.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/wagoodman/dive">wagoodman/dive</a></td>
        <td>A tool for exploring each layer in a docker image</td>
    </tr>
    <tr>
        <td><a href="https://github.com/xmendez/wfuzz">xmendez/wfuzz</a></td>
        <td>Wfuzz has been created to facilitate the task in web applications assessments and it is based on a simple concept: it replaces any reference to the FUZZ keyword by the value of a given payload.</td>
    </tr>
	<tr>
		<td><a href="https://github.com/Yelp/detect-secrets">Yelp/detect-secrets</a></td>
		<td>An enterprise friendly way of detecting and preventing secrets in code.</td>
	</tr>
    <tr>
        <td><a href="https://github.com/ZupIT/horusec">ZupIT/horusec</a></td>
        <td>Horusec is an open source tool that improves identification of vulnerabilities in your project with just one command.</td>
    </tr>
</table>

## Binary Analysis

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/acsdavid97/DotNetHooker">acsdavid97/DotNetHooker</a></td>
        <td>API tracing and argument dumping to ease reverse engineering .NET malware.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/advanced-threat-research/DotDumper">advanced-threat-research/DotDumper</a></td>
        <td>An automatic unpacker and logger for DotNet Framework targeting files</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Air14/HyperHide">Air14/HyperHide</a></td>
        <td>Hypervisor based anti anti debug plugin for x64dbg</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ajpc500/RelayRumbler">ajpc500/RelayRumbler</a></td>
        <td>A proof-of-concept tool that attempts to retrieve the configuration from the memory dump of an F-Secure C3 Relay executable.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/avast-tl/retdec">avast-tl/retdec</a></td>
        <td>RetDec is a retargetable machine-code decompiler based on LLVM</td>
    </tr>
    <tr>
        <td><a href="https://github.com/binref/refinery">binref/refinery</a></td>
        <td>High Octane Triage Analysis</td>
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
        <td><a href="https://git.sr.ht/~prabhu/blint">BLint</a></td>
        <td>BLint is a Binary Linter to check the security properties, and capabilities in your executables. It is powered by lief</td>
    </tr>
    <tr>
        <td><a href="https://github.com/bohops/RogueAssemblyHunter">bohops/RogueAssemblyHunter</a></td>
        <td>Rogue Assembly Hunter is a utility for discovering 'interesting' .NET CLR modules in running processes.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/bootleg/ret-sync">bootleg/ret-sync</a></td>
        <td>ret-sync is a set of plugins that helps to synchronize a debugging session (WinDbg/GDB/LLDB/OllyDbg2/x64dbg) with IDA/Ghidra disassemblers.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/buzzer-re/Shinigami/">buzzer-re/Shinigami</a></td>
        <td>Shinigami is an experimental tool designed to detect and unpack malware implants that are injected via process hollowing or generic packer routines.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/can1357/NoVmp">can1357/NoVmp</a></td>
        <td>A static devirtualizer for VMProtect x64 3.x. powered by VTIL.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/carbonblack/binee">carbonblack/binee</a></td>
        <td>Binee: binary emulation environment</td>
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
        <td><a href="https://github.com/certcc/kaiju">certcc/kaiju</a></td>
        <td>CERT Kaiju is a binary analysis framework extension for the Ghidra software reverse engineering suite</td>
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
        <td><a href="https://dogbolt.org/">Decompiler Explorer</a></td>
        <td>This is the Decompiler Explorer! It is an interactive online decompiler which shows equivalent C-like output of decompiled programs from many popular decompilers. It's meant to be the reverse of the amazing Compiler Explorer.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/dr4k0nia/Unscrambler">dr4k0nia/Unscrambler</a></td>
        <td>Universal unpacker and fixer for a number of modded ConfuserEx protections</td>
    </tr>
    <tr>
        <td><a href="https://github.com/dragon-dreamer/binary-valentine">dragon-dreamer/binary-valentine</a></td>
        <td>Binary Valentine is a cross-platform static analysis tool for Portable Executable files. Detects security, configuration, optimization, system and format issues.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/e-m-b-a/emba">e-m-b-a/emba</a></td>
        <td>EMBA - The firmware security analyzer</td>
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
        <td><a href="https://github.com/FernandoDoming/r2diaphora">FernandoDoming/r2diaphora</a></td>
        <td>r2diaphora is a port of Diaphora to radare2 and MySQL. It also uses r2ghidra as decompiler by default, with support for other decompilers such as pdc.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/fireeye/flare-emu">flare-emu</a></td>
        <td>flare-emu marries a supported binary analysis framework, such as IDA Pro or Radare2, with Unicorns emulation framework to provide the user with an easy to use and flexible interface for scripting emulation tasks.</td>
    </tr>
    <tr>
        <td><a href="https://www.fibratus.io/">fibratus</a></td>
        <td>A modern tool for the Windows kernel exploration and observability</td>
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
        <td><a href="https://github.com/fireeye/flare-floss">fireeye/flare-floss</a></td>
        <td>FireEye Labs Obfuscated String Solver - Automatically extract obfuscated strings from malware.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/fireeye/speakeasy">fireeye/speakeasy</a></td>
        <td>Speakeasy is a portable, modular, binary emulator designed to emulate Windows kernel and user mode malware.</td>
    </tr>
    <tr>
	    <td><a href="https://github.com/fireeye/stringsifter">fireeye/stringsifter</a></td>
	    <td>A machine learning tool that ranks strings based on their relevance for malware analysis.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/fkie-cad/FACT_core">fkie-cad/FACT_core</a></td>
        <td>Firmware Analysis and Comparison Tool</td>
    </tr>
    <tr>
        <td><a href="https://github.com/forrest-orr/moneta">forrest-orr/moneta</a></td>
        <td>Moneta is a live usermode memory analysis tool for Windows with the capability to detect malware IOCs</td>
    </tr>
    <tr>
        <td><a href="https://github.com/FuzzySecurity/Dendrobate">FuzzySecurity/Dendrobate</a></td>
        <td>Managed code hooking template.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/FuzzySecurity/Fermion">FuzzySecurity/Fermion</a></td>
        <td>Fermion, an electron wrapper for Frida & Monaco.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/gaasedelen/tenet">gaasedelen/tenet</a></td>
        <td>A Trace Explorer for Reverse Engineers</td>
    </tr>
    <tr>
        <td><a href="https://github.com/GaloisInc/reopt">GaloisInc/reopt</a></td>
        <td>A tool for analyzing x86-64 binaries.</td>
    </tr>
    <tr>
        <td><a href="https://ghidra-sre.org/">GHIDRA</a></td>
        <td>A software reverse engineering (SRE) suite of tools developed by NSA's Research Directorate in support of the Cybersecurity mission</td>
    </tr>
    <tr>
        <td><a href="https://github.com/goretk/redress">goretk/redress</a></td>
        <td>Redress - A tool for analyzing stripped Go binaries</td>
    </tr>
    <tr>
        <td><a href="https://github.com/grimm-co/GEARSHIFT">grimm-co/GEARSHIFT</a></td>
        <td>GEARSHIFT is a tool that performs structure recovery for a specified function within a stripped binary. It also generates a fuzz harness that can be used to call functions in a shared object (.so) or dynamically linked library (.dll) file.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/guelfoweb/peframe">guelfoweb/peframe</a></td>
        <td>PEframe is a open source tool to perform static analysis on Portable Executable malware and malicious MS Office documents.</td>
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
        <td><a href="https://github.com/hasherezade/pe_to_shellcode">hasherezade/pe_to_shellcode</a></td>
        <td>Converts PE into a shellcode</td>
    </tr>
    <tr>
        <td><a href="https://github.com/herosi/CTO">herosi/CTO</a></td>
        <td>Call Tree Overviewer</td>
    </tr>
    <tr>
        <td><a href="https://github.com/horsicq/XELFViewer">horsicq/XELFViewer</a></td>
        <td>ELF file viewer/editor for Windows, Linux and MacOS.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/HyperDbg/HyperDbg">HyperDbg/HyperDbg</a></td>
        <td>The Source Code of HyperDbg Debugger 🐞</td>
    </tr>
    <tr>
        <td><a href="https://github.com/hzqst/unicorn_pe">hzqst/unicorn_pe</a></td>
        <td>Unicorn PE is an unicorn based instrumentation project designed to emulate code execution for windows PE files.</td>
    </tr>
    <tr>
        <td><a href="https://kaitai.io">Kaitai Struct</a></td>
        <td>Kaitai Struct is a declarative language used to describe various binary data structures, laid out in files or in memory: i.e. binary file formats, network stream packet formats, etc.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/KeenSecurityLab/BinAbsInspector">KenSecurityLab/BinAbsInspector</a></td>
        <td>BinAbsInspector: Vulnerability Scanner for Binaries</td>
    </tr>
    <tr>
        <td><a href="https://lief.quarkslab.com/">LIEF</a></td>
        <td>Library to Instrument Executable Formats</td>
    </tr>
    <tr>
        <td><a href="https://github.com/loov/lensm">loov/lensm</a></td>
        <td>Go assembly and source viewer</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mandiant/dncil">mandiant/dncli</a></td>
        <td>The FLARE team's open-source library to disassemble Common Intermediate Language (CIL) instructions.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mandiant/GoReSym">mandiant/GoReSym</a></td>
        <td>Go symbol recovery tool</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mandiant/route-sixty-sink">mandiant/route-sixty-sink</a></td>
        <td>Link sources to sinks in C# applications.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Martyx00/CollaRE">Martyx00/CollaRE</a></td>
        <td>CollareRE is a tool for collaborative reverse engineering that aims to allow teams that do need to use more then one tool during a project to collaborate without the need to share the files on a separate locations.</td>
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
        <td><a href="https://github.com/MITRECND/malchive">MITRECND/malchive</a></td>
        <td>Various capabilities for static malware analysis.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/moyix/gpt-wpre">moyix/gpt-wpre</a></td>
        <td>Whole-Program Reverse Engineering with GPT-3</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mrphrazer/obfuscation_detection">mrphrazer/obfuscation_detection</a></td>
        <td>Collection of scripts to pinpoint obfuscated code</td>
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
        <td><a href="https://github.com/nsacyber/BAM">nsacyber/BAM</a></td>
        <td>The Binary Analysis Metadata tool gathers information about Windows binaries to aid in their analysis.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/nccgroup/WindowsMemPageDelta">nccgroup/WindowsMemPageDelta</a></td>
        <td>A Microsoft Windows service to provide telemetry on Windows executable memory page changes to facilitate threat detection</td>
    </tr>
    <tr>
        <td><a href="https://github.com/netspooky/scare">netspooky/scare</a></td>
        <td>A multi-arch assembly REPL and emulator for your command line.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/OALabs/hashdb-ida">OALabs/hashdb-ida</a></td>
        <td>HashDB API hash lookup plugin for IDA Pro</td>
    </tr>
    <tr>
        <td><a href="https://github.com/osandov/drgn">osandov/drgn</a></td>
        <td>Programmable debugger</td>
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
        <td><a href="https://github.com/revng/pagebuster">revng/pagebuster</a></td>
        <td>PageBuster - dump all executable pages of packed processes.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/REW-sploit/REW-sploit">REW-sploit/REW-sploit</a></td>
        <td>Emulate and Dissect MSF and *other* attacks</td>
    </tr>
    <tr>
        <td><a href="https://rizin.re/">rizin</a></td>
        <td>Free and Open Source Reverse Engineering Framework</td>
    </tr>
    <tr>
        <td><a href="https://github.com/secretsquirrel/recomposer">secretsquirrel/recomposer</a></td>
        <td>Randomly changes Win32/64 PE Files for 'safer' uploading to malware and sandbox sites.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/sibears/IDAGolangHelper">sibears/IDAGolangHelper</a></td>
        <td>Set of IDA Pro scripts for parsing GoLang types information stored in compiled binary</td>
    </tr>
    <tr>
        <td><a href="https://github.com/strazzere/golang_loader_assist">strazzere/golang_loader_assist</a></td>
        <td>Making GO reversing easier in IDA Pro</td>
    </tr>
    <tr>
        <td><a href="https://github.com/synacktiv/frinet">synacktive/frinet</a></td>
        <td>Frida-based tracer for easier reverse-engineering on Android, iOS, Linux, Windows and most related architectures.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/taviso/loadlibrary">taviso/loadlibrary</a></td>
        <td>Porting Windows Dynamic Link Libraries to Linux</td>
    </tr>
    <tr>
        <td><a href="https://github.com/unipacker/unipacker">unipacker/unipacker</a></td>
        <td>Automatic and platform-independent unpacker for Windows binaries based on emulation</td>
    </tr>
    <tr>
        <td><a href="https://github.com/utkonos/lst2x64dbg">utkonos/lst2x64dbg</a></td>
        <td>Extract labels from IDA, Ghidra, Binary Ninja, and Relyze files and export x64dbg database. Including radare2 main address.</td>
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
        <td><a href="https://githacks.org/vmp2/vmemu">vmp2/vmemu</a></td>
        <td>VMProtect 2 Virtual Machine Handler Emulation</td>
    </tr>
    <tr>
        <td><a href="https://github.com/wader/fq">wader/fq</a></td>
        <td>Tool, language and decoders for inspecting binary data.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Wenzel/checksec.py">Wenzel/checksec.py</a></td>
        <td>Checksec tool in Python, Rich output. Based on LIEF</td>
    </tr>
    <tr>
        <td><a href="https://github.com/WerWolv/ImHex">WerWolv/ImHex</a></td>
        <td>A Hex Editor for Reverse Engineers, Programmers and people that value their eye sight when working at 3 AM.</td>
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
        <td><a href="https://github.com/aws-cloudformation/cloudformation-guard">aws-cloudformation/cloudformation-guard</a></td>
        <td>Guard offers a policy-as-code domain-specific language (DSL) to write rules and validate JSON- and YAML-formatted data such as CloudFormation Templates, K8s configurations, and Terraform JSON plans/configurations against those rules.</td>
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
        <td><a href="https://github.com/AzureAD/Azure-AD-Incident-Response-PowerShell-Module">AzureAD/Azure-AD-Incident-Response-PowerShell-Module</a></td>
        <td>The Azure Active Directory Incident Response PowerShell module provides a number of tools, developed by the Azure Active Directory Product Group in conjunction with the Microsoft Detection and Response Team (DART), to assist in compromise response.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/BishopFox/iam-vulnerable">BishopFox/iam-vulnerable</a></td>
        <td>Use Terraform to create your own vulnerable by design AWS IAM privilege escalation playground.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/BishopFox/smogcloud">BishopFox/smogcloud</a></td>
        <td>Find cloud assets that no one wants exposed</td>
    </tr>
    <tr>
        <td><a href="https://github.com/BloodHoundAD/AzureHound">BloodHoundAD/AzureHound</a></td>
        <td>Azure Hound</td>
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
        <td><a href="https://github.com/carlospolop/PurplePanda">carlospolop/PurplePanda</a></td>
        <td>Identify privilege escalation paths within and across different clouds</td>
    </tr>
    <tr>
        <td><a href="https://github.com/carnal0wnage/weirdAAL/wiki">carnal0wnage/weirdAAL</a></td>
        <td>WeirdAAL [AWS Attack Library] wiki!</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cisagov/Sparrow">cisagov/Sparrow</a></td>
        <td>Sparrow.ps1 was created by CISA's Cloud Forensics team to help detect possible compromised accounts and applications in the Azure/m365 environment.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cisagov/untitledgoosetool">cisagov/untitledgoosetool</a></td>
        <td>Untitled Goose Tool is a robust and flexible hunt and incident response tool that adds novel authentication and data gathering methods in order to run a full investigation against a customer’s Azure Active Directory (AzureAD), Azure, and M365 environments.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cloud-sniper/cloud-sniper">cloud-sniper/cloud-sniper</a></td>
        <td>Cloud Security Operations Orchestrator</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cloudquery/cloudquery">cloudquery/cloudquery</a></td>
        <td>cloudquery transforms your cloud infrastructure into queryable SQL tables for easy monitoring, governance and security.</td>
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
        <td><a href="https://github.com/CrowdStrike/CRT">CrowdStrike/CRT</a></td>
        <td>This tool queries the following configurations in the Azure AD/O365 tenant which can shed light on hard to find permissions and configuration settings in order to assist organizations in securing these environments.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cyberark/blobhunter">cyberark/blobhunter</a></td>
        <td>Find exposed data in Azure with this public blob scanner</td>
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
        <td><a href="https://github.com/darkbitio/aws-recon">darkbitio/aws-recon</a></td>
        <td>Multi-threaded AWS inventory collection tool with a focus on security-relevant resources and metadata.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/darkquasar/AzureHunter">darkquasar/AzureHunter</a></td>
        <td>A Cloud Forensics Powershell module to run threat hunting playbooks on data from Azure and O365</td>
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
        <td><a href="https://github.com/FSecureLABS/Azurite">FSecureLABS/Azurite</a></td>
        <td>Enumeration and reconnaissance activities in the Microsoft Azure Cloud.</td>
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
        <td><a href="https://github.com/initstring/cloud_enum">initstring/cloud_enum</a></td>
        <td>Multi-cloud OSINT tool. Enumerate public resources in AWS, Azure, and Google Cloud.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/jonrau1/ElectricEye">jonrau1/ElectricEye</a></td>
        <td>Continuously monitor your AWS services for configurations that can lead to degradation of confidentiality, integrity or availability. All results will be sent to Security Hub for further aggregation and analysis.</td>
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
        <td><a href="https://github.com/kromtech/s3-inspector">kromtech/s3-inspector</a></td>
        <td>Tool to check AWS S3 bucket permissions</td>
    </tr>
    <tr>
        <td><a href="https://github.com/lyft/metadataproxy">lyft/metadataproxy</a></td>
        <td>A proxy for AWS's metadata service that gives out scoped IAM credentials from STS</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Macmod/STARS">Macmod/STARS</a></td>
        <td>A multi-cloud DNS record scanner that aims to help cybersecurity/IT analysts identify dangling CNAME records in their cloud DNS services that could possibly lead to subdomain takeover scenarios.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mgeeky/AzureRT">mgeeky/AzureRT</a></td>
        <td>AzureRT - A Powershell module implementing various Azure Red Team tactics</td>
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
        <td><a href="https://github.com/rootsecdev/Azure-Red-Team">nccgroup/azucar</a></td>
        <td>Security auditing tool for Azure environments</td>
    </tr>
    <tr>
        <td><a href="https://github.com/nccgroup/PMapper">nccgroup/PMapper</a></td>
        <td>A tool for quickly evaluating IAM permissions in AWS.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/nccgroup/s3_objects_check">nccgroup/s3_objects_check</a></td>
        <td>Whitebox evaluation of effective S3 object permissions, in order to identify publicly accessible objects.</td>
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
        <td><a href="https://github.com/NetSPI/MicroBurst">NetSPI/MicroBurst</a></td>
        <td>A collection of scripts for assessing Microsoft Azure security</td>
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
        <td><a href="https//github.com/projectdiscovery/cloudlist">projectdiscovery/cloudlist</a></td>
        <td>Cloudlist is a tool for listing Assets from multiple Cloud Providers.</td>
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
        <td><a href="https://github.com/RhinoSecurityLabs/cloudgoat">RhinoSecurityLabs/cloudgoat</a></td>
        <td>CloudGoat is Rhino Security Labs' "Vulnerable by Design" AWS deployment tool</td>
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
        <td><a href="https://github.com/soteria-security/365Inspect">soteria-security/365Inspect</a></td>
        <td>A PowerShell script that automates the security assessment of Microsoft Office 365 environments.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/spacesiren/spacesiren">spacesiren/spacesiren</a></td>
        <td>A honey token manager and alert system for AWS.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/sbasu7241/AWS-Threat-Simulation-and-Detection">sbasu7241/AWS-Threat-Simulation-and-Detection</a></td>
        <td>Playing around with Stratus Red Team (Cloud Attack simulation tool) and SumoLogic</td>
    </tr>
    <tr>
        <td><a href="https://github.com/swimlane/CLAW">swimlane/CLAW</a></td>
        <td>A packer utility to create and capture DFIR Image for use AWS & Azure</td>
    </tr>
    <tr>
        <td><a href="https://github.com/theflakes/reg_hunter">theflakes/reg_hunter</a></td>
        <td>Blueteam operational triage registry hunting/forensic tool</td>
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
        <td><a href="https://github.com/Balasys/dheater">Balasys/dheater</a></td>
        <td>D(HE)ater is a security tool can perform DoS attack by enforcing the DHE key exchange.</td>
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
        <td><a href="https://github.com/Demonslay335/CryptoTester">Demonslay335/CryptoTester</a></td>
        <td>A utility for playing with cryptography, geared towards ransomware analysis.</td>
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
        <td><a href="https://github.com/mxrch/evilize">mxrch/evilize</a></td>
        <td>Use md5-collisions to make evil executables looking like a good one.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/salesforce/ja3">salesforce/ja3</td>
        <td>JA3 is a standard for creating SSL client fingerprints in an easy to produce and shareable way.</td>
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
        <td><a href="https://dataplane.org/">DataPlane.org</a></td>
        <td>DataPlane.org is a community-powered Internet data, feeds, and measurement resource for operators, by operators. We provide reliable and trustworthy service at no cost.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/fox-it/cobaltstrike-beacon-data">cobaltstrike-beacon-data</a></td>
        <td>Open Dataset of Cobalt Strike Beacon metadata (2018-2022)</td>
    </tr>
    <tr>
        <td><a href="https://toolbox.google.com/datasetsearch">Google Dataset Search</a></td>
        <td>Google Dataset Search</td>
    </tr>
    <tr>
        <td><a href="https://github.com/FiveDirections/OpTC-data">FiveDirections/OpTC-data</a></td>
        <td>Operationally Transparent Cyber (OpTC) Data</td>
    </tr>
    <tr>
        <td><a href="https://github.com/intel/yarpgen">intel/yarpgen</a></td>
        <td>Yet Another Random Program Generator</td>
    </tr>
    <tr>
        <td><a href="https://www.kaggle.com/ymirsky/network-attack-dataset-kitsune">Kitsune Network Attack Dataset</a></td>
        <td>Nine labeled attacks with extracted features and the original network capture</td>
    </tr>
    <tr>
        <td><a href="https://github.com/nimrodpar/Labeled-Elfs">nimrodpar/Labeled-Elfs</a></td>
        <td>A collection of well labeled ELF binaries compiled from benign and malicious code in various ways. Great for exploring similarity in executables and training various ML models.</td>
    </tr>
    <tr>
        <td><a href="https://securitydatasets.com/introduction.html">Security Datasets</a></td>
        <td>The Security Datasets project is an open-source initiatve that contributes malicious and benign datasets, from different platforms, to the infosec community to expedite data analysis and threat research.</td>
    </tr>
    <tr>
        <td><a href="http://www.secrepo.com/">SecRepo.com - Samples of Security Related Data</a></td>
        <td>Finding samples of various types of Security related can be a giant pain. This is my attempt to keep a somewhat curated list of Security related data I've found, created, or was pointed to. If you perform any kind of analysis with any of this data please let me know and I'd be happy to link it from here or host it here. Hopefully by looking at others research and analysis it will inspire people to add-on, improve, and create new ideas.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/sophos-ai/SOREL-20M">sophos-ai/SOREL-20M</a></td>
        <td>Sophos-ReversingLabs 20 million sample dataset</td>
    </tr>
    <tr>
        <td><a href="https://github.com/splunk/attack_data">splunk/attack_data</a></td>
        <td>A Repository of curated datasets from various attacks</td>
    </tr>
    <tr>
        <td><a href="https://winbindex.m417z.com/">Winbindex</a></td>
        <td>The Windows Binaries Index</td>
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
        <td><a href="https://github.com/0xrawsec/kunai">0xrawsec/kunai</a></td>
        <td>Threat-hunting tool for Linux</td>
    </tr>
    <tr>
        <td><a href="https://github.com/3CORESec/Automata">3CORESec/Automata</a></td>
        <td>Automatic detection engineering technical state compliance</td>
    </tr>
    <tr>
        <td><a href="https://github.com/AbdulRhmanAlfaifi/Fennec">AbdulRhmanAlfaifi/Fennec</a></td>
        <td>Artifact collection tool for *nix systems</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Accenture/docker-plaso">Accenture/docker-plaso</a></td>
        <td>Docker container for plaso supertimlining tool</td>
    </tr>
    <tr>
        <td><a href="https://github.com/activecm/BeaKer">activecm/BeaKer</a></td>
        <td>Beacon Kibana Executable Report. Aggregates Sysmon Network Events With Elasticsearch and Kibana</td>
    </tr>
    <tr>
        <td><a href="https://github.com/activecm/espy/">activecm/espy/</a></td>
        <td>Endpoint detection for remote hosts for consumption by RITA and Elasticsearch</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ahmedkhlief/APT-Hunter">ahmedkhlief/APT-Hunter</a></td>
        <td>APT-Hunter is Threat Hunting tool for windows event logs which made by purple team mindset to provide detect APT movements hidden in the sea of windows event logs to decrease the time to uncover suspicious activity</td>
    </tr>
    <tr>
        <td><a href="https://github.com/airbus-cert/Winshark">airbus-cert/Winshark</a></td>
        <td>A wireshark plugin to instrument ETW</td>
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
        <td><a href="https://github.com/ANSSI-FR/DFIR4vSphere">ANSSI-FR/DFIR4vSphere</a></td>
        <td>Powershell module for VMWare vSphere forensics</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ANSSI-FR/DFIR-O365RC">ANSSI-FR/DFIR-O365RC</a></td>
        <td>PowerShell module for Office 365 and Azure AD log collection</td>
    </tr>
    <tr>
        <td><a href="https://github.com/aquasecurity/tracee">aquasecurity/tracee</a></td>
        <td>Linux Runtime Security and Forensics using eBPF</td>
    </tr>
    <tr>
        <td><a href="https://arsenalrecon.com/downloads/">Arsenal Recon Free Tools</a></td>
        <td>Arsenal Recon Free Tools</td>
    </tr>
    <tr>
        <td><a href="https://github.com/asimihsan/cwl-mount">asimihsan/cwl-mount</a></td>
        <td>Mount AWS CloudWatch logs as a file system</td>
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
        <td><a href="https://github.com/BSI-Bund/RdpCacheStitcher">BSI-Bund/RdpCacheStitcher</a></td>
        <td>RdpCacheStitcher is a tool that supports forensic analysts in reconstructing useful images out of RDP cache bitmaps.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cado-security/varc">cado-security/varc</a></td>
        <td>Volatile Artifact Collector collects a snapshot of volatile data from a system. It tells you what is happening on a system, and is of particular use when investigating a security incident.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/carmaa/inception">carmaa/inception</a></td>
        <td>Inception is a physical memory manipulation and hacking tool exploiting PCI-based DMA. The tool can attack over FireWire, Thunderbolt, ExpressCard, PC Card and any other PCI/PCIe interfaces.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/CCob/BeaconEye">CCob/BeaconEye</a></td>
        <td>Hunts out CobaltStrike beacons and logs operator command output</td>
    </tr>
    <tr>
        <td><a href="https://www.cerebrate-project.org/">Cerebrate Project</a></td>
        <td>Cerebrate is an open-source platform meant to act as a trusted contact information provider and interconnection orchestrator for other security tools (such as MISP).</td>
    </tr>
    <tr>
        <td><a href="https://github.com/chrisandoryan/Nethive-Project">chrisandoryan/Nethive-Project</a></td>
        <td>Restructured and Collaborated SIEM and CVSS Infrastructure. Presented at Blackhat Asia Arsenal 2020.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cilium/tetragon">cilium/tetragon</a></td>
        <td>eBPF-based Security Observability and Runtime Enforcement</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cisagov/CHIRP">cisagov/CHIRP</a></td>
        <td>A forensic collection tool written in Python.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/coinbase/dexter">coinbase/dexter</a></td>
        <td>Forensics acquisition framework designed to be extensible and secure</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ComodoSecurity/openedr">ComodoSecurity/openedr</a></td>
        <td>Open EDR public repository</td>
    </tr>
    <tr>
        <td><a href="https://github.com/countercept/chainsaw">countercept/chainsaw</a></td>
        <td>Rapidly Search and Hunt through Windows Event Logs</td>
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
        <td><a href="https://github.com/CrowdStrike/SuperMem">CrowdStrike/SuperMem</a></td>
        <td>A python script developed to process Windows memory images based on triage type.</td>
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
        <td><a href="https://github.com/D4stiny/PeaceMaker">D4stiny/PeaceMaker</a></td>
        <td>PeaceMaker Threat Detection is a Windows kernel-based application that detects advanced techniques used by malware.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/DamonMohammadbagher/ETWProcessMon2">DamonMohammadbagher/ETWProcessMon2</a></td>
        <td>ETWProcessMon2 is for Monitoring Process/Thread/Memory/Imageloads/TCPIP via ETW + Detection for Remote-Thread-Injection etc.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/DataDog/threatest">DataDog/threatest</a></td>
        <td>Threatest is a Go framework for end-to-end testing threat detection rules.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/davehull/Kansa">davehull/Kansa</a></td>
        <td>A Powershell incident response framework</td>
    </tr>
    <tr>
        <td><a href="https://github.com/deepalert/deepalert">deepalert/deepalert</a></td>
        <td>Serverless SOAR (Security Orchestration, Automation and Response) framework for automatic inspection and evaluation of security alert</td>
    </tr>
    <tr>
        <td><a href="https://dfir-orc.github.io/">DFIR ORC</a></td>
        <td>DFIR ORC, where ORC stands for “Outil de Recherche de Compromission” in French, is a collection of specialized tools dedicated to reliably parse and collect critical artefacts such as the MFT, registry hives or event logs. It can also embed external tools and their configurations.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/dfir-iris/iris-web">dfir-iris/iris-web</a></td>
        <td>Incident Response collaborative platform</td>
    </tr>
    <tr>
        <td><a href="https://github.com/DFIRKuiper/Kuiper">DFIRKuiper/Kuiper</a></td>
        <td>Digital Forensics Investigation Platform</td>
    </tr>
    <tr>
        <td><a href="https://github.com/dfirtrack/dfirtrack">dfirtrack/dfirtrack</a></td>
        <td>DFIRTrack - The Incident Response Tracking Application</td>
    </tr>
    <tr>
        <td><a href="https://info.digitalguardian.com/wingman.html">DG Wingman</a></td>
        <td>DG Wingman is a free community Windows tool designed to aid in the collection of forensic evidence in order to properly investigate and scope an intrusion.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/dhondta/AppmemDumper">dhondta/AppmemDumper</a></td>
        <td>Forensics triage tool relying on Volatility and Foremost</td>
    </tr>
    <tr>
        <td><a href="https://github.com/dlcowen/FSEventsParser">dlcowen/FSEventsParser</a></td>
        <td>Parser for OSX/iOS FSEvents Logs</td>
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
        <td><a href="https://github.com/elastic/protections-artifacts">elastic/protections-artifacts</a></td>
        <td>Elastic Security detection content for Endpoint</td>
    </tr>
    <tr>
        <td><a href="https://github.com/emalderson/ThePhish">emalderson/ThePhish</a></td>
        <td>ThePhish: an automated phishing email analysis tool</td>
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
        <td><a href="https://github.com/fireeye/ThreatPursuit-VM">fireeye/ThreatPursuit-VM</a></td>
        <td>Threat Pursuit Virtual Machine (VM): A fully customizable, open-sourced Windows-based distribution focused on threat intelligence analysis and hunting designed for intel and malware analysts as well as threat hunters to get up and running quickly.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ForensicArtifacts/artifacts">ForensicArtifacts/artifacts</a></td>
        <td>Digital Forensics Artifact Repository</td>
    </tr>
    <tr>
        <td><a href="https://github.com/frikky/Shuffle">frikky/Shuffle</a></td>
        <td>Shuffle: A general purpose security automation platform platform. We focus on accessibility for all.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/FSecureLABS/LinuxCatScale">FSecureLABS/LinuxCatScale</a></td>
        <td>Incident Response collection and processing scripts with automated reporting scripts</td>
    </tr>
    <tr>
        <td><a href="https://github.com/G-Research/siembol">G-Research/siembol</a></td>
        <td>An open-source, real-time Security Information & Event Management tool based on big data technologies, providing a scalable, advanced security analytics framework.</td>
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
        <td><a href="https://github.com/google/timesketch">google/timesketch</a></td>
        <td>Collaborative forensic timelune analysis</td>
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
        <td><a href="https://github.com/hashlookup/hashlookup-forensic-analyser">hashlookup/hashlookup-forensic-analyser</a></td>
        <td>Analyse a forensic target (such as a directory) to find and report files found and not found from CIRCL hashlookup public service</td>
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
        <td><a href="https://github.com/jimtin/IRCoreForensicFramework">jimtin/IRCoreForensicFramework</a></td>
        <td>Powershell 7 (Powershell Core)/ C# cross platform forensic framework. Built by incident responders for incident responders.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/jklepsercyber/defender-detectionhistory-parser">jklepsercyber/defender-detectionhistory-parser</a></td>
        <td>A parser of Windows Defender's DetectionHistory forensic artifact, containing substantial info about quarantined files and executables.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/joeavanzato/Trawler">joeavanzato/Trawler</a></td>
        <td>PowerShell script to help Incident Responders discover adversary persistence mechanisms.</td>
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
        <td><a href="https://github.com/invictus-ir/Microsoft-365-Extractor-Suite">invictus-ir/Microsoft-365-Extractor-Suite</a></td>
        <td>A set of PowerShell scripts that allow for complete and reliable acquisition of the Microsoft 365 Unified Audit Log</td>
    </tr>
   <tr>
        <td><a href="https://github.com/Invoke-IR/ACE">Invoke-IR/ACE</a></td>
        <td>The Automated Collection and Enrichment (ACE) platform is a suite of tools for threat hunters to collect data from many endpoints in a network and automatically enrich the data. The data is collected by running scripts on each computer without installing any software on the target. ACE supports collecting from Windows, macOS, and Linux hosts.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Invoke-IR/PowerForensics">Invoke-IR/PowerForensics</a></td>
        <td>PowerForensics provides an all in one platform for live disk forensic analysis</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ion-storm/sysmon-edr">ion-storm/sysmod-edr</a></td>
        <td>Sysmon EDR Active Response</td>
    </tr>
    <tr>
        <td><a href="https://github.com/kacos2000/MFT_Browser">kacos2000/MFT_Browser</a></td>
        <td>$MFT directory tree reconstruction & record info</td>
    </tr>
    <tr>
        <td><a href="https://securelist.com/happy-ir-in-the-new-year/83557/">Kaspersky IR's Artifacts Collector</a></td>
        <td>Kaspersky IR's Artifacts Collector</td>
    </tr>
    <tr>
        <td><a href="https://www.brimorlabsblog.com/2019/04/live-response-collection-cedarpelta.html">Live Response Collection - Cedarpelta</a></td>
        <td>Live Response Collection - Cedarpelta </td>
    </tr>
    <tr>
        <td><a href="https://github.com/log2timeline/dftimewolf">log2timeline/dftimewolf</a></td>
        <td>A framework for orchestrating forensic collection, processing and data export</td>
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
        <td><a href="https://github.com/mandiant/Mandiant-Azure-AD-Investigator">mandiant/Mandiant-Azure-AD-Investigator</a></td>
        <td>This repository contains a PowerShell module for detecting artifacts that may be indicators of UNC2452 and other threat actor activity</td>
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
        <td><a href="https://github.com/matanolabs/matano">matanolabs/matano</a></td>
        <td>Open source cloud-native security lake platform (SIEM alternative) for threat hunting, detection & response, and cybersecurity analytics at petabyte scale on AWS</td>
    </tr>
    <tr>
        <td><a href="https://github.com/microsoft/avml">microsoft/avml</a></td>
        <td>AVML - Acquire Volatile Memory for Linux</td>
    </tr>
    <tr>
        <td><a href="https://github.com/miriamxyra/EventList">miriamxyra/EventList</a></td>
        <td>EventList is a tool to help improving your Audit capabilities and to help to build your Security Operation Center.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mitre-attack/bzar">mitre-attack/bzar</a></td>
        <td>A set of Zeek scripts to detect ATT&CK techniques.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/monnappa22/HollowFind">monnappa22/HollowFind</a></td>
        <td>Hollowfind is a Volatility plugin to detect different types of process hollowing techniques used in the wild to bypass, confuse, deflect and divert the forensic analysis techniques. The plugin detects such attacks by finding discrepancy in the VAD and PEB, it also disassembles the address of entry point to detect any redirection attempts and als…</td>
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
        <td><a href="https://github.com/Neo23x0/god-mode-rules">Neo23x0/god-mode-rules</a></td>
        <td>God Mode Detection Rules</td>
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
        <td><a href="https://github.com/NVISOsecurity/evtx-hunter">NVISOsecurity/evtx-hunter</a></td>
        <td>evtx-hunter helps to quickly spot interesting security-related activity in Windows Event Viewer (EVTX) files.</td>
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
        <td><a href="https://github.com/omenscan/achoirx">omenscan/achoirx</a></td>
        <td>ReWrite of AChoir in Go for Cross PlatformReWrite of AChoir in Go for Cross Platform</td>
    </tr>
    <tr>
        <td><a href="https://github.com/opencybersecurityalliance/kestrel-lang">opencybersecurityalliance/kestrel-lang</a></td>
        <td>Kestrel Threat Hunting Language</td>
    </tr>
    <tr>
        <td><a href="https://github.com/OpenEx-Platform/openex">OpenEx-Platform/openex</a></td>
        <td>Open Crisis Exercises Planning Platform</td>
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
        <td><a href="https://github.com/OTRF/Azure-Sentinel2Go">OTRF/Azure-Sentinel2Go</a></td>
        <td>Azure Sentinel2Go is an open source project developed to expedite the deployment of an Azure Sentinel lab.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ovotech/gitoops/">ovotech/gitoops</a></td>
        <td>GitOops is a tool to help attackers and defenders identify lateral movement and privilege escalation paths in GitHub organizations by abusing CI/CD pipelines and GitHub access controls.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/philhagen/sof-elk">philhagen/sof-elk</a></td>
        <td>Configuration files for the SOF-ELK VM, used in SANS FOR572</td>
    </tr>
    <tr>
        <td><a href="https://github.com/PSGumshoe/PSGumshoe">PSGumshoe/PSGumshoe</a></td>
        <td>PSGumshoe is a Windows PowerShell module for the collection of OS and domain artifacts for the purposes of performing live response, hunt, and forensics.</td>
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
        <td><a href="https://pulsar.sh/">PULSAR</a></td>
        <td>Pulsar is a powerful, blazing fast runtime security observability framework designed for the IoT.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/PwC-IR/Office-365-Extractor">PwC-IR/Office-365-Extractor</a></td>
        <td>The Office 365 Extractor is a tool that allows for complete and reliable extraction of the Unified Audit Log (UAL)</td>
    </tr>
    <tr>
        <td><a href="https://github.com/rajiv2790/FalconEye">rajiv2790/FalconEye</a></td>
        <td>FalconEye: Real-time detection software for Windows process injections</td>
    </tr>
    <tr>
        <td><a href="https://redcanary.com/blog/mac-monitor/">Red Canary Mac Monitor</a></td>
        <td>Red Canary Mac Monitor is a feature-rich dynamic analysis tool for macOS that leverages our extensive understanding of the platform and Apple’s latest APIs to collect and present relevant security events.</td>
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
        <td><a href="https://rocknsm.io/">ROCK NSM</a></td>
        <td>Response Operation Collection Kit - An open source Network Security Monitoring platform.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/salesforce/bro-sysmon/">salesforce/bro-sysmon</td>
        <td>Bro-Sysmon enables Bro to receive Windows Event Logs. This provide a method to associate Network Monitoring and Host Monitoring. The work was spurred by the need to associate JA3 and HASSH fingerprints with the application on the host. The example below shows the hostname, Process ID, connection information, JA3 fingerprints, Application Path, and binary hashes.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/salesforce/jarm">salesforce/jarm</a></td>
        <td>JARM is an active Transport Layer Security (TLS) server fingerprinting tool.</td>
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
        <td><a href="https://github.com/SecurityBrewery/catalyst">SecurityBrewery/catalyst</a></td>
        <td>Catalyst is a SOAR system that helps to automate alert handling and incident response processes</td>
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
        <td><a href="https://github.com/shellster/DCSYNCMonitor">shellster/DCSYNCMonitor</a></td>
        <td>Monitors for DCSYNC and DCSHADOW attacks and create custom Windows Events for these events.</td>
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
        <td><a href="https://github.com/splunk/melting-cobalt">splunk/melting-cobalt</a></td>
        <td>A Cobalt Strike Scanner that retrieves detected Team Server beacons into a JSON object</td>
    </tr>
    <tr>
        <td><a href="https://github.com/sumeshi/evtx2es">sumeshi/evtx2es</a></td>
        <td>A library for fast import of Windows Eventlogs into Elasticsearch.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/swisscom/Invoke-Forensics">swisscom/Invoke-Forensics</a></td>
        <td>Invoke-Forensics provides PowerShell commands to simplify working with the forensic tools KAPE and RegRipper.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Sysinternals/SysmonForLinux">Sysinternals/SysmonForLinux</a></td>
        <td>Sysmon For Linux install and build instructions</td>
    </tr>
    <tr>
        <td><a href="https://github.com/tap-ir/tapir">tap-ir/tapir</a></td>
        <td>TAPIR is a multi-user, client/server, incident response framework</td>
    </tr>
    <tr>
        <td><a href="https://github.com/tclahr/uac">tclahr/uac</a></td>
        <td>UAC (Unix-like Artifacts Collector) is a Live Response collection tool for Incident Reponse that makes use of built-in tools to automate the collection of Unix-like systems artifacts. Supported systems: AIX, FreeBSD, Linux, macOS, NetBSD, Netscaler, OpenBSD and Solaris.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/telekom-security/acquire-aws-ec2">telekom-security/acquire-aws-ec2</a></td>
        <td>A python script to acquire multiple aws ec2 instances in a forensically sound-ish way</td>
    </tr>
    <tr>
        <td><a href="https://www.cgsecurity.org/wiki/TestDisk">TestDisk</a></td>
        <td>TestDisk is powerful free data recovery software! It was primarily designed to help recover lost partitions and/or make non-booting disks bootable again when these symptoms are caused by faulty software: certain types of viruses or human error (such as accidentally deleting a Partition Table). Partition table recovery using TestDisk is really easy.</td>
    </tr>
    <tr>
        <td><a href="https://www.sleuthkit.org/">The Sleuth Kit</a></td>
        <td>sleuthkit.org is the official website for The Sleuth Kit®, Autopsy®, and other open source digital investigation tools. From here, you can find documents, case studies, and download the latest versions of the software.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/thewhiteninja/ntfstool">thewhiteninja/ntfstool</a></td>
        <td>Forensics tool for NTFS (parser, mft, bitlocker, deleted files)</td>
    </tr>
    <tr>
        <td><a href="https://github.com/THIBER-ORG/userline">THIBER-ORG/userline</a></td>
        <td>Query and report user logons relations from MS Windows Security Events</td>
    </tr>
    <tr>
        <td><a href="https://github.com/threathunters-io/laurel">threathunters-io/laurel</a></td>
        <td>Transform Linux Audit logs for SIEM usage</td>
    </tr>
    <tr>
        <td><a href="https://github.com/TobySalusky/cont3xt">TobySalusky/cont3xt</a></td>
        <td>Cont3xt intends to centralize and simplify a structured approach to gathering contextual intelligence in support of technical investigations.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/travisfoley/dfirtriage">travisfoley/dfirtriage</a></td>
        <td>Digital forensic acquisition tool for Windows based incident response.</td>
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
        <td><a href="https://binaryforay.blogspot.com/2018/09/introducing-vscmount.html">VSCMount</a></td>
        <td>Volume shadow copies mounter tool</td>
    </tr>
    <tr>
        <td><a href="https://wazuh.com/">Wazuh</a></td>
        <td>Open Source Host and Endpoint Security</td>
    </tr>
    <tr>
        <td><a href="https://github.com/wagga40/Zircolite">wagga40/Zircolite</a></td>
        <td>A standalone SIGMA-based detection tool for EVTX.</td>
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
        <td><a href="https://github.com/XForceIR/SideLoadHunter">XForceIR/SideLoadHunter</a></td>
        <td>SideLoadHunter is a PowerShell script and Sysmon configuration designed to aide defenders and incident responders identify evidence of DLL sideloading on Windows systems.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Yamato-Security/hayabusa">Yamato-Security/hayabusa</a></td>
        <td>Hayabusa is a threat hunting and fast forensics timeline generator for Windows event logs.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Yamato-Security/WELA">Yamato-Security/WELA</a></td>
        <td>WELA (Windows Event Log Analyzer): The Swiss Army knife for Windows Event Logs! ゑ羅（ウェラ)</td>
    </tr>
    <tr>
        <td><a href="https://github.com/yampelo/beagle">yampelo/beagle</a></td>
        <td>Beagle is an incident response and digital forensics tool which transforms security logs and data into graphs.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/zeronetworks/RPCFirewall">zeronetworks/RPCFirewall</a></td>
        <td>RPC is the underlying mechanism which is used for numerous lateral movement techniques, reconnaisense, relay attacks, or simply to exploit vulnerable RPC services.</td>
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
        <td><a href="https://github.com/itm4n/Perfusion">itm4n/Perfusion</a></td>
        <td>Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)</td>
    </tr>
    <tr>
        <td><a href="https://github.com/itm4n/UsoDllLoader">itm4n/UsoDllLoader</a></td>
        <td>Windows - Weaponizing privileged file writes with the Update Session Orchestrator service</td>
    </tr>
    <tr>
        <td><a href="https://github.com/nomi-sec/PoC-in-GitHub">nomi-sec/PoC-in-GitHub</a></td>
        <td>📡 PoC auto collect from GitHub. ⚠️ Be careful Malware.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/opencve/opencve">opencve/opencve</a></td>
        <td>CVE Alerting Platform</td>
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
        <td><a href="https://github.com/0x6d69636b/windows_hardening">0x6d69636b/windows_hardening</a></td>
        <td>Windows Hardening settings and configurations</td>
    </tr>
    <tr>
        <td><a href="https://hub.steampipe.io/mods/turbot/azure_compliance/controls/benchmark.nist_sp_800_53_rev_5">Benchmark: NIST SP 800-53 Revision 5</a></td>
        <td>NIST SP 800-53 Revision 5 represents a multi-year effort to develop the next generation of security and privacy controls needed to strengthen and support the U.S. federal government. These next generation controls offer a proactive and systematic approach to ensure that critical systems, components, and services are sufficiently trustworthy and have the necessary resilience to defend the economic and national security interests of the United States.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cisagov/cset">cisagov/cset</a></td>
        <td>Cybersecurity Evaluation Tool</td>
    </tr>
    <tr>
        <td><a href="https://github.com/elastic/PPLGuard">elastic/PPLGuard</a></td>
        <td>PPLGuard is a proof of concept tool that can mitigate two currently-unpatched Windows security flaws which pose threats to Protected Processes Light (PPL) processes, such as AntiMalware services.</td>
    </tr>
    <tr>
        <td><a href="https://linuxreviews.org/Linux_Kernel_Runtime_Guard">Linux Kernel Runtime Guard</a></td>
        <td>Linux Kernel Runtime Guard (LKRG) is a out-of-tree security module for the Linux kernel developed by Openwall. It does run-time integrity checks in order to stop known, and unknown, security vulnerabilities in the Linux kernel. It can log detected intrusion attempts or stop them by causing a kernel panic - resulting in a frozen machine or a reboot depending on how the kernel is configured.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/nccgroup/exploit_mitigations">nccgroup/exploit_mitigations</a></td>
        <td>Knowledge base of exploit mitigations available across numerous operating systems, architectures and applications and versions.</td>
    </tr>
    <tr>
        <td><a href="https://privacy.sexy/">Privacy.sexy</a></td>
        <td>Enforce privacy & security on Windows and macOS</td>
    </tr>
    <tr>
        <td><a href="https://santa.dev/">Santa</a></td>
        <td>Santa is a binary authorization system for macOS</td>
    </tr>
    <tr>
        <td><a href="https://public.cyber.mil/stigs/">Security Technical Implementation Guides (STIGs)</a></td>
        <td>The Security Technical Implementation Guides (STIGs) are the configuration standards for DOD IA and IA-enabled devices/systems.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/securitywithoutborders/hardentools"></a>securitywithoutborders/hardentools</td>
        <td>Hardentools simply reduces the attack surface on Microsoft Windows computers by disabling low-hanging fruit risky features.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ukncsc/Device-Security-Guidance-Configuration-Packs">ukncsc/Device-Security-Guidance-Configuration-Packs</a></td>
        <td>This repository contains policy packs which can be used by system management software to configure device platforms (such as Windows 10 and iOS) in accordance with NCSC device security guidance. These configurations are aimed primarily at government and other medium/large organisations.</td>
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
        <td><a href="https://github.com/MaximeBeasse/KeyDecoder">MaximeBeasse/KeyDecoder</a></td>
        <td>KeyDecoder app lets you use your smartphone or tablet to decode your mechanical keys in seconds.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Theldus/bread">Theldus/bread</a></td>
        <td>🍞 BREAD: BIOS Reverse Engineering & Advanced Debugging</td>
    </tr>
    <tr>
        <td><a href="https://github.com/tothi/usbgadget-tool">tothi/usbgadget-tool</a></td>
        <td>Dumb USB HID gadget creator for Android (for triggering device driver install on Windows for LPE)</td>
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
        <td><a href="https://github.com/accidentalrebel/mbcscan">accidentalrebel/mbcscan</a></td>
        <td>Scans a malware file and lists down the related MBC (Malware Behavior Catalog) details.</td>
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
        <td><a href="https://github.com/advanced-threat-research/DarkSide-Config-Extract">advanced-threat-research/DarkSide-Config-Extract</a></td>
        <td>DarkSide & BlackMatter Config Extractor by ValthekOn & S2 (@sisoma2)</td>
    </tr>
    <tr>
        <td><a href="https://github.com/advanced-threat-research/IOCs">advanced-threat-research/IOCs</a></td>
        <td>Repository containing IOCs, MISP and Expert rules from our blogs</td>
    </tr>
    <tr>
        <td><a href="https://github.com/akamai/luda">akamai/luda</a></td>
        <td>Malicious actors often reuse code to deploy their malware, phishing website or CNC server. As a result, similiaries can be found on URLs path by inspecting internet traffic. Moreover, deep learning models or even regular ML model do not fit for inline deployment in terms of running performance. However, regexes ( or YARA rules ) can be deployed …</td>
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
        <td><a href="https://github.com/captainGeech42/ransomwatch">captainGeech42/ransomwatch</a></td>
        <td>Ransomware leak site monitoring</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cert-ee/cuckoo3">cert-ee/cuckoo3</a></td>
        <td>Cuckoo 3 is a Python 3 open source automated malware analysis system.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/CERT-Polska/drakvuf-sandbox">CERT-Polska/drakvuf-sandbox</a></td>
        <td>DRAKVUF Sandbox - automated hypervisor-level malware analysis system</td>
    </tr>
    <tr>
        <td><a href="https://github.com/CERT-Polska/karton/">CERT-Polska/karton</a></td>
        <td>Distributed malware processing framework based on Python, Redis and MinIO.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/CERT-Polska/mwdb-core">CERT-Polska/mwdb-core</a></td>
        <td>Malware repository component for samples & static configuration with REST API interface.</td>
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
        <td><a href="https://github.com/CRED-CLUB/ARTIF">CRED-CLUB/ARTIF</a></td>
        <td>An advanced real time threat intelligence framework to identify threats and malicious web traffic on the basis of IP reputation and historical data.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/CriticalPathSecurity/Zeek-Intelligence-Feeds">CriticalPathSecurity/Zeek-Intelligence-Feeds</a></td>
        <td>Zeek-Formatted Threat Intelligence Feeds</td>
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
        <td><a href="https://github.com/csvl/SEMA-ToolChain">csvl/SEMA-ToolChain</a></td>
        <td>ToolChain using Symbolic Execution for Malware Analysis.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/CybercentreCanada/CCCS-Yara">CybercentreCanada/CCCS-Yara</a></td>
        <td>YARA rule metadata specification and validation utility / Spécification et validation pour les règles YARA</td>
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
        <td><a href="https://github.com/dsnezhkov/racketeer">dsnezhkov/racketeer</a></td>
        <td>Racketeer Project - Ransomware emulation toolkit</td>
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
        <td><a href="https://github.com/FortyNorthSecurity/WMImplant">FortyNorthSecurity/WMImplant</a></td>
        <td>This is a PowerShell based tool that is designed to act like a RAT. Its interface is that of a shell where any command that is supported is translated into a WMI-equivalent for use on a network/remote machine. WMImplant is WMI based.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/godaddy/procfilter">godaddy/procfilter</a></td>
        <td>A YARA-integrated process denial framework for Windows</td>
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
        <td><a href="https://github.com/hasherezade/mal_unpack">hasherezade/mal_unpack</a></td>
        <td>Dynamic unpacker based on PE-sieve</td>
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
        <td><a href="https://github.com/hejelylab/easeYARA">hejelylab/easeYARA</a></td>
        <td>C# Desktop GUI application that either performs YARA scan locally or prepares the scan in Active Directory domain environment with a few clicks.</td>
    </tr>
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
        <td><a href="https://github.com/fortinet/ips-bph-framework">ips-bph-framework</a></td>
        <td>BLACKPHENIX is an open source malware analysis automation framework composed of services, scripts, plug-ins, and tools and is based on a Command-and-Control (C&C) architecture</td>
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
        <td><a href="https://github.com/JohnHammond/vbe-decoder">JohnHammond/vbe-decoder</a></td>
        <td>A Python3 script to decode an encoded VBScript file, often seen with a .vbe file extension</td>
    </tr>
    <tr>
        <td><a href="https://github.com/JohnLaTwC/PyPowerShellXray">JohnLaTwC/PyPowerShellXray</a></td>
        <td>Python script to decode common encoded PowerShell scripts</td>
    </tr>
    <tr>
        <td><a href="https://github.com/jstrosch/malware-samples">jstrosch/malware-samples</a></td>
        <td>Malware samples, analysis exercises and other interesting resources.</td>
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
        <td><a href="https://github.com/kevoreilly/CAPEv2">kevoreilly/CAPEv2</a></td>
        <td>Malware Configuration And Payload Extraction</td>
    </tr>
    <tr>
        <td><a href="https://github.com/kirk-sayre-work/VBASeismograph">kirk-sayre-work/VBASeismograph</a></td>
        <td>A tool for detecting VBA stomping.</td>
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
        <td><a href="https://github.com/mandiant/apooxml">mandiant/apooxml</a></td>
        <td>Generate YARA rules for OOXML documents.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/marcosd4h/memhunter">marcosd4h/memhunter</a></td>
        <td>Live hunting of code injection techniques</td>
    </tr>
   <tr>
        <td><a href="https://github.com/maliceio/malice">maliceio/malice</a></td>
        <td>Malice's mission is to be a free open source version of VirusTotal that anyone can use at any scale from an independent researcher to a fortune 500 company.</td>
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
        <td><a href="https://github.com/matterpreter/DefenderCheck">matterpreter/DefenderCheck</a></td>
        <td>Identifies the bytes that Microsoft Defender flags on.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mindcollapse/MalwareMultiScan">mindcollapse/MalwareMultiScan</a></td>
        <td>Self-hosted VirusTotal / MetaDefender wannabe with API, demo UI and Scanners running in Docker.</td>
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
        <td><a href="https://github.com/oasis-open/cti-stix-generator">oasis-open/cti-stix-generator</a></td>
        <td>OASIS Cyber Threat Intelligence (CTI) TC: A tool for generating STIX content for prototyping and testing.</td>
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
        <td><a href="https://github.com/pandora-analysis/pandora">pandora-analysis/pandora</a></td>
        <td>Pandora is an analysis framework to discover if a file is suspicious and conveniently show the results</td>
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
        <td><a href="https://github.com/SentineLabs/SentinelLabs_RevCore_Tools">SentineLabs/SentinelLabs_RevCore_Tools</a></td>
        <td>The Windows Malware Analysis Reversing Core Tools</td>
    </tr>
    <tr>
        <td><a href="https://github.com/slaughterjames/excelpeek">slaughterjames/excelpeek</a></td>
        <td>ExcelPeek is a tool designed to help investigate potentially malicious Microsoft Excel files.</td>
    </tr>
    <tr>
		<td><a href="https://github.com/sophos-ai/yaraml_rules">sophos-ai/yaraml_rules</a></td>
		<td>Security ML models encoded as Yara rules</td>
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
        <td><a href="https://github.com/strozfriedberg/cobaltstrike-config-extractor">strozfriedberg/cobaltstrike-config-extractor</a></td>
        <td>Cobalt Strike Beacon configuration extractor and parser.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/t4d/PhishingKitHunter">t4d/PhishingKitHunter</a></td>
        <td>Find phishing kits which use your brand/organization's files and image.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/target/halogen">target/halogen</a></td>
        <td>Automatically create YARA rules from malicious documents.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ThisIsLibra/MalPull">ThisIsLibra/MalPull</a></td>
        <td>A CLI interface to search for a MD-5/SHA-1/SHA-256 hash on multiple malware databases and download the sample from the first hit</td>
    </tr>
    <tr>
        <td><a href="https://github.com/tklengyel/drakvuf">tklengyel/drakvuf</a></td>
        <td>DRAKVUF Black-box Binary Analysis</td>
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
        <td><a href="https://github.com/uqcyber/ColdPress">uqcyber/ColdPress</a></td>
        <td>Extensible Platform for Malware Analysis</td>
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
        <td><a href="https://github.com/W3ndige/aurora">W3ndige/aurora</a></td>
        <td>Malware similarity platform with modularity in mind.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/xorhex/mlget">xorhex/mlget</a></td>
        <td>A golang CLI tool to download malware from a variety of sources.</td>
    </tr>
    <tr>
        <td><a href="https://yaradbg.dev/">YaraDbg</a></td>
        <td>YaraDbg is a free web-based Yara debugger to help security analysts to write hunting or detection rules with less effort and more confidence.</td>
    </tr>
    <tr>
        <td><a href="https://yaraify.abuse.ch/">YARAify</a></td>
        <td>YARAify is a project from abuse.ch that allows anyone to scan suspicious files such as malware samples or process dumps against a large repository of YARA rules. With YARAhub, the platform also provides a structured way for sharing YARA rules with the community.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/zerofox-oss/phishpond">zerofox-oss/phishpond</a></td>
        <td>Because phishtank was taken.. explore phishing kits in a contained environment!</td>
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
        <td><a href="https://www.apkdetect.com/">apkdetect</a></td>
        <td>Android malware analysis and classification platform</td>
    </tr>
    <tr>
        <td><a href="https://ibotpeaches.github.io/Apktool/">Apktool</a></td>
        <td>A tool for reverse engineering Android apk files</td>
    </tr>
    <tr>
        <td><a href="https://github.com/as0ler/r2flutch">as0ler/r2flutch</a></td>
        <td>Tool to decrypt iOS apps using r2frida</td>
    </tr>
    <tr>
        <td><a href="https://github.com/chaitin/passionfruit">chaitin/passionfruit</a></td>
        <td>Simple iOS app blackbox assessment tool. Powered by frida.re and vuejs.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/charles2gan/GDA-android-reversing-Tool">charles2gan/GDA-android-reversing-Tool</a></td>
        <td>GDA is a new fast and powerful decompiler in C++(working without Java VM) for the APK, DEX, ODEX, OAT, JAR, AAR, and CLASS file. which supports malicious behavior detection, privacy leaking detection, vulnerability detection, path solving, packer identification, variable tracking, deobfuscation, python&java scripts, device memory extraction, dat</td>
    </tr>
    <tr>
        <td><a href="https://github.com/dpnishant/appmon">dpnishant/appmon</a></td>
        <td>AppMon is an automated framework for monitoring and tampering system API calls of native macOS, iOS and android apps. It is based on Frida.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/dmayer/idb">dmayer/idb</a></td>
        <td>idb is a tool to simplify some common tasks for iOS pentesting and research</td>
    </tr>
    <tr>
        <td><a href="https://github.com/WithSecureLabs/drozer">Drozer</a></td>
        <td>Comprehensive security and attack framework for Android</td>
    </tr>
    <tr>
        <td><a href="https://github.com/dwisiswant0/apkleaks">dwisiswant0/apkleaks</a></td>
        <td>Scanning APK file for URIs, endpoints & secrets.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/facebook/mariana-trench/">facebook/mariana-trench</a></td>
        <td>Our security focused static analysis tool for Android and Java applications.</td>
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
        <td><a href="https://github.com/mvt-project/mvt">mvt-project/mvt</a></td>
        <td>MVT is a forensic tool to look for signs of infection in smartphone devices</td>
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
        <td><a href="https://beta.pithus.org/about/">Pithus</a></td>
        <td>Pithus is a free and open-source mobile threat intelligence platform for activists, journalists, NGOs, researchers...</td>
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
        <td><a href="https://github.com/RealityNet/kobackupdec">RealityNet/kobackupdec</a></td>
        <td>Huawei backup decryptor</td>
    </tr>
    <tr>
        <td><a href="https://github.com/securing/IOSSecuritySuite">securing/IOSSecuritySuite</a></td>
        <td>iOS platform security & anti-tampering Swift library</td>
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
        <td><a href="https://arkime.com/">Arkime</a></td>
        <td>Arkime (formerly Moloch) is a large scale, open source, indexed packet capture and search tool.</td>
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
        <td><a href="https://github.com/Ben0xA/HoneyCreds">Ben0xA/HoneyCreds</a></td>
        <td>HoneyCreds network credential injection to detect responder and other network poisoners.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/certego/PcapMonkey">certego/PcapMonkey</a></td>
        <td>PcapMonkey will provide an easy way to analyze pcap using the latest version of Suricata and Zeek.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/chadillac/UPnProxyPot">chadillac/UPnProxyPot</a></td>
        <td>An SSDP & UPNP honeypot implementation aimed at intercepting/tracking UPnProxy campaigns.</td>
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
        <td><a href="https://github.com/cisco/mercury">cisco/mercury</a></td>
        <td>Mercury: network metadata capture and analysis</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ddosify/ddosify">ddosify/ddosify</a></td>
        <td>High-performance load testing tool, written in Golang.</td>
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
        <td><a href="https://github.com/eciavatta/caronte">eciavatta/caronte</a></td>
        <td>A tool to analyze the network flow during attack/defence capture the flag competitions</td>
    </tr>
    <tr>
        <td><a href="https://github.com/eldraco/domain_analyzer/">eldraco/domain_analyzer</a></td>
        <td>Analyze the security of any domain by finding all the information possible. Made in python.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/firefart/stunner/">firefart/stunner</a></td>
        <td>Stunner is a tool to test and exploit STUN, TURN and TURN over TCP servers</td>
    </tr>
    <tr>
        <td><a href="https://github.com/fireeye/flare-fakenet-ng">fireeye/flare-fakenet-ng</a></td>
        <td>FakeNet-NG - Next Generation Dynamic Network Analysis Tool</td>
    </tr>
    <tr>
        <td><a href="https://github.com/qeeqbox/chameleon">qeeqbox/chameleon</a></td>
        <td>Customizable honeypots for monitoring network traffic, bots activities and username\password credentials (DNS, HTTP Proxy, HTTP, HTTPS, SSH, POP3, IMAP, STMP, RDP, VNC, SMB, SOCKS5, Redis, TELNET, Postgres and MySQL)</td>
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
        <td><a href="https://github.com/nesfit/NetfoxDetective/">nesfit/NetfoxDetective</a></td>
        <td>NFX Detective is a novel Network forensic analysis tool that implements methods for extraction of application content from communication using supported protocols.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/odedshimon/BruteShark">odedshimon/BruteShark</a></td>
        <td>BruteShark is a Network Forensic Analysis Tool (NFAT) that performs deep processing and inspection of network traffic (mainly PCAP files)</td>
    </tr>
    <tr>
        <td><a href="https://packettotal.com/">PacketTotal</a></td>
        <td>A free, online PCAP analysis engine</td>
    </tr>
    <tr>
    </tr>
        <td><a href="https://github.com/Phenomite/AMP-Research">Phenomite/AMP-Research</a></td>
        <td>Research on UDP/TCP amplification vectors, payloads and mitigations against their use in DDoS Attacks</td>
    </tr>
    <tr>
        <td><a href="https://www.netresec.com/?page=PolarProxy">PolarProxy</a></td>
        <td>PolarProxy is a transparent SSL/TLS proxy created for incident responders and malware researchers. PolarProxy is primarily designed to intercept and decrypt TLS encrypted traffic from malware. PolarProxy decrypts and re-encrypts TLS traffic, while also saving the decrypted traffic in a PCAP file that can be loaded into Wireshark or an intrusion detection system (IDS).</td>
    </tr>
    <tr>
        <td><a href="https://github.com/secureworks/dalton">secureworks/dalton</a></td>
        <td>Suricata and Snort IDS rule and pcap testing system</td>
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
        <td><a href="https://github.com/ValtteriL/UPnProxyChain">ValtteriL/UPnProxyChain</a></td>
        <td>A tool to create a SOCKS proxy server out of UPnProxy vulnerable device(s).</td>
    </tr>
    <tr>
        <td><a href="https://github.com/vincentbernat/akvorado">vincentbernat/akvorado</a></td>
        <td>Flow collector, hydrater and visualizer</td>
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
        <td><a href="https://github.com/americanexpress/earlybird">americanexpress/earlybird</a></td>
        <td>EarlyBird is a sensitive data detection tool capable of scanning source code repositories for clear text password violations, PII, outdated cryptography methods, key files and more.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/arch4ngel/peasant">arch4ngel/peasant</a></td>
        <td>LinkedIn reconnaissance tool</td>
    </tr>
    <tr>
        <td><a href="http://bit.ly/bcattools">Bellingcat's Online Investigation Toolkit</a></td>
        <td>Welcome to Bellingcats freely available online open source investigation toolkit.</td>
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
        <td><a href="https://start.me/p/EL84Km/cse-utopia">CSE Utopia</a></td>
        <td>CSE Utopia</td>
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
        <td><a href="https://darksearch.io/">DarkSearch</a></td>
        <td>The 1st Real Dark Web Search Engine</td>
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
        <td><a href="https://github.com/dgtlmoon/changedetection.io">dgtlmoon/changedetection.io</a></td>
        <td>changedetection.io - The best and simplest self-hosted open source website change detection monitoring and notification service. An alternative to Visualping, Watchtower etc. Designed for simplicity - the main goal is to simply monitor which websites had a text change. Open source web page change detection - Now also includes JSON API change det…</td>
    </tr>
    <tr>
        <td><a href="https://github.com/felix83000/Watcher">felix83000/Watcher</a></td>
        <td>Watcher - Open Source Cybersecurity Threat Hunting Platform. Developed with Django & React JS.</td>
    </tr>
    <tr>
        <td><a href="https://tools.epieos.com/google-account.php">Epieos Tools - Google Account Finder</a></td>
        <td>An online tool to retrieve sensitive information like google maps reviews, public photos, displayed name, usage of google services such as YouTube, Hangouts</td>
    </tr>
    <tr>
        <td><a href="https://grep.app/">grep.app</a></td>
        <td>Search across a half million git repos</td>
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
        <td><a href="https://github.com/hessman/gcert">hessman/gcert</a></td>
        <td>Retrieves information about a given domain from the Google Transparency Report</td>
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
        <td><a href="https://blog.shodan.io/introducing-the-internetdb-api/">InternetDB</a></td>
        <td>Fast IP Lookups for Open Ports and Vulnerabilities</td>
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
        <td><a href="https://github.com/khast3x/h8mail">khast3x/h8mail</a></td>
        <td>Email OSINT & Password breach hunting tool, locally or using premium services. Supports chasing down related email</td>
    </tr>
    <tr>
        <td><a href="https://github.com/knownsec/Kunyu">knownsec/Kunyu</a></td>
        <td>Kunyu, more efficient corporate asset collection</td>
    </tr>
    <tr>
        <td><a href="https://github.com/lanrat/certgraph">lanrat/certgraph</a></td>
        <td>An open source intelligence tool to crawl the graph of certificate Alternate Names</td>
    </tr>
    <tr>
	    <td><a href="https://leakix.net/">LeakIX</a></td>
	    <td>This project goes around the internet and finds services to index them.</td>
    </tr>
    <tr>
        <td><a href="https://leak-lookup.com/">Leak-Lookup</a></td>
        <td>Data Breach Search Engine</td>
    </tr>
    <tr>
        <td><a href="https://github.com/leapsecurity/InSpy">leapsecurity/InSpy</a></td>
        <td>A python based LinkedIn enumeration tool</td>
    </tr>
    <tr>
        <td><a href="https://lookyloo.circl.lu/">Lookyloo</a></td>
        <td>Web forensics tool</td>
    </tr>
    <tr>
        <td><a href="https://github.com/loseys/Oblivion">loseys/Oblivion</a></td>
        <td>Data leak checker & OSINT Tool</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Malfrats/xeuledoc">Malfrats/xeuledoc</a></td>
        <td>Fetch information about a public Google document.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/medialab/minet">medialab/minet</a></td>
        <td>A webmining CLI tool & library for python.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/megadose/holehe">megadose/holehe</a></td>
        <td>holehe allows you to check if the mail is used on different sites like twitter, instagram and will retrieve information on sites with the forgotten password function.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mxrch/ghunt">mxrch/ghunt</a></td>
        <td>GHunt is an OSINT tool to extract a lot of informations of someone's Google Account email.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/nccgroup/scrying">nccgroup/scrying</a></td>
        <td>A tool for collecting RDP, web and VNC screenshots all in one place</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ninoseki/mihari">ninoseki/mihari</a></td>
        <td>A helper to run OSINT queries & manage results continuously</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ninoseki/mitaka">ninoseki/mikata</a></td>
        <td>A browser extension for OSINT search</td>
    </tr>
    <tr>
        <td><a href="https://aleph.occrp.org/">OCCRP Aleph</a></td>
        <td>The global archive of research material for investigative reporting.</td>
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
        <td><a href="https://opencorporates.com/">OpenCorporates</a></td>
        <td>Legal-entity data you can trust</td>
    </tr>
    <tr>
        <td><a href="https://www.openownership.org/en/">Open Ownership</a></td>
        <td>Open Ownership drives the global shift towards transparency and accountability in corporate ownership and control</td>
    </tr>
    <tr>
        <td><a href="https://osint.sh/">OSINT.SH</a></td>
        <td>ALL IN ONE INFORMATION GATHERING TOOLS</td>
    </tr>
    <tr>
        <td><a href="https://github.com/OWASP/Amass">OWASP/Amass</a></td>
        <td>In-depth Attack Surface Mapping and Asset Discovery</td>
    </tr>
    <tr>
        <td><a href="https://github.com/PaperMtn/gitlab-watchman">PaperMtn/gitlab-watchman</a></td>
        <td>Monitoring GitLab for sensitive data shared publicly</td>
    </tr>
    <tr>
        <td><a href="https://psbdmp.ws/">Pastebin dump collection</a></td>
        <td>Pastebin dump collection</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Patrowl/PatrowlHears">Patrowl/PatrowlHears</a></td>
        <td>PatrowlHears - Vulnerability Intelligence Center / Exploits</td>
    </tr>
    <tr>
        <td><a href="https://phonebook.cz/">Phonebook.cz</a></td>
        <td>Phonebook lists all domains, email addresses, or URLs for the given input domain.</td>
    </tr>
    <tr>
		<td><a href="https://github.com/qeeqbox/social-analyzer">qeeqbox/social-analyzer</a></td>
		<td>API, CLI & Web App for analyzing & finding a person's profile across 350+ social media websites (Detections are updated regularly)</td>
	</tr>
    <tr>
		<td><a href="https://hackertarget.com/recon-ng-tutorial/">Recon-NG</a></td>
		<td>Recon-ng is a reconnaissance tool with an interface similar to Metasploit. Running recon-ng from the command line you enter a shell like environment where you can configure options, perform recon and output results to different report types.</td>
	</tr>
    <tr>
        <td><a href="https://www.gov.uk/government/collections/register-of-overseas-entities">Register of Overseas Entities</a></td>
        <td>Overseas entities who want to buy, sell or transfer property or land in the UK, must register with Companies House and tell us who their registrable beneficial owners or managing officers are.</td>
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
        <td><a href="https://shademap.app/">Shade Map</a></td>
        <td>View Shade on Map</td>
    </tr>
    <tr>
        <td><a href="https://github.com/sherlock-project/sherlock">sherlock-project/sherlock</a></td>
        <td>🔎 Hunt down social media accounts by username across social networks</td>
    </tr>
    <tr>
        <td><a href="https://snusbase.com/">SnusBase</a></td>
        <td>The longest standing data breach search engine.</td>
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
        <td><a href="https://github.com/sundowndev/PhoneInfoga">sundowndev/PhoneInfoga</a></td>
        <td>Advanced information gathering & OSINT framework for phone numbersAdvanced information gathering & OSINT framework for phone numbers</td>
    </tr>
    <tr>
        <td><a href="https://github.com/superhedgy/AttackSurfaceMapper">superhedgy/AttackSurfaceMapper</a></td>
        <td>AttackSurfaceMapper is a tool that aims to automate the reconnaissance process.</td>
    </tr>
    <tr>
        <td><a href="https://ted.europa.eu/en/news/welcome-to-the-new-ted">TED</a></td>
        <td>Tenders Electronic Daily</td>
    </tr>
    <tr>
        <td><a href="https://github.com/thewhiteh4t/nexfil">thewhiteh4t/nexfil</a></td>
        <td>OSINT tool for finding profiles by username</td>
    </tr>
    <tr>
        <td><a href="https://tor.taxi/">tor.taxi</a></td>
        <td>tor.taxi - your ride to the darknet</td>
    </tr>
	<tr>
        <td><a href="https://github.com/vysecurity/LinkedInt">vysecurity/LinkedInt</a></td>
        <td>LinkedIn Recon Tool</td>
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
    <tr>
        <td><a href="https://github.com/yogeshojha/rengine">yogeshojha/rengine</a></td>
        <td>reNgine is an automated reconnaissance framework meant for information gathering during penetration testing of web applications. reNgine has customizable scan engines, which can be used to scan the websites, endpoints, and gather information.</td>
    </tr>
</table>

## Password Cracking and Wordlists

<table>
    <tr>
        <td><a href="https://wordlists.assetnote.io/">Assetnote Wordlists</a></td>
        <td>Automated & Manual Wordlists provided by Assetnote</td>
    </tr>
    <tr>
        <td><a href="https://github.com/berzerk0/Probable-Wordlists">berzerk0/Probable-Wordlists</a></td>
        <td>Wordlists sorted by probability originally created for password generation and testing - make sure your passwords aren't popular!</td>
    </tr>
    <tr>
        <td><a href="https://github.com/byt3bl33d3r/SprayingToolkit">byt3bl33d3r/SprayingToolkit</a></td>
        <td>Scripts to make password spraying attacks against Lync/S4B & OWA a lot quicker, less painful and more efficient</td>
    </tr>
    <tr>
        <td><a href="https://github.com/c6fc/npk">c6fc/npk</a></td>
        <td>A mostly-serverless distributed hash cracking platform</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Coalfire-Research/npk">Coalfire-Research/npk</a></td>
        <td>A mostly-serverless distributed hash cracking platform</td>
    </tr>
    <tr>
        <td><a href="https://github.com/f0cker/crackq">f0cker/crackq</a></td>
        <td>CrackQ: A Python Hashcat cracking queue system</td>
    </tr>
    <tr>
        <td><a href="https://github.com/fireeye/gocrack">fireeye/gocrack</a></td>
        <td>GoCrack provides APIs to manage password cracking tasks across supported cracking engines.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/JoelGMSec/Cloudtopolis">JoelGMSec/Cloudtopolis</a></td>
        <td>Zero Infrastructure Password Cracking</td>
    </tr>
    <tr>
        <td><a href="https://gitlab.com/l0phtcrack/l0phtcrack">l0phtcrack/l0phtcrack</a></td>
        <td>L0phtCrack Password Auditor</td>
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
        <td><a href="https://github.com/bitsadmin/fakelogonscreen">bitsadmin/fakelogonscreen</a></td>
        <td>Fake Windows logon screen to steal passwords</td>
    </tr>
    <tr>
        <td><a href="https://github.com/BiZken/PhishMailer">BiZken/PhishMailer</a></td>
        <td>Generate Professional Phishing Emails Fast And Easy</td>
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
		<td><a href="https://emailrep.io/">Emailrep.io</a></td>
		<td>Illuminate the "reputation" behind an email address</td>
	</tr>
    <tr>
        <td><a href="https://fakeyou.com">FakeYou Text to Speech</a></td>
        <td>Use deep fake tech to say stuff with your favorite characters.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/fireeye/ReelPhish">fireeye/ReelPhish</a></td>
        <td>ReelPhish: A Real-Time Two-Factor Phishing Tool</td>
    </tr>
    <tr>
        <td><a href="https://github.com/fkasler/phishmonger">fkasler/phishmonger</a></td>
        <td>Phishing Framework for Pentesters</td>
    </tr>
    <tr>
        <td><a href="https://github.com/GemGeorge/SniperPhish/">GemGeorge/SniperPhish/</a></td>
        <td>SniperPhish - The Web-Email Spear Phishing Toolkit</td>
    </tr>
    <tr>
        <td><a href="https://github.com/gophish/gophish">gophish/gophish</a></td>
        <td>Gophish is an open-source phishing toolkit designed for businesses and penetration testers. It provides the ability to quickly and easily setup and execute phishing engagements and security awareness training</td>
    </tr>
    <tr>
        <td><a href="https://github.com/htr-tech/zphisher">htr-tech/zphisher</a></td>
        <td>An automated phishing tool with 30+ templates.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/kgretzky/evilginx2">kgretzky/evilginx2</a></td>
        <td>Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies, allowing for the bypass of 2-factor authentication</td>
    </tr>
	<tr>
		<td><a href="https://github.com/mdsecactivebreach/o365-attack-toolkit">mdsecactivebreach/o365-attack-toolkit</a></td>
		<td>o365-attack-toolkit allows operators to perform an OAuth phishing attack and later on use the Microsoft Graph API to extract interesting information.</td>
	</tr>
    <tr>
        <td><a href="https://github.com/Mr-Un1k0d3r/CatMyPhish">Mr-Un1k0d3r/CatMyPhish</a></td>
        <td>Search for categorized domain</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mrd0x/BITB">mrd0x/BITB</a></td>
        <td>Browser In The Browser (BITB) Templates</td>
    </tr>
	<tr>
		<td><a href="https://github.com/muraenateam/muraena">muraenateam/muraena</a></td>
		<td>Muraena is an almost-transparent reverse proxy aimed at automating phishing and post-phishing activities.</td>
	</tr>
    <tr>
        <td><a href="https://github.com/Octoberfest7/TeamsPhisher">Octoberfest7/TeamPhisher</a></td>
        <td>Send phishing messages and attachments to Microsoft Teams users</td>
    </tr>
    <tr>
        <td><a href="https://github.com/optiv/Microsoft365_devicePhish">optiv/Microsoft365_devicePhish</a></td>
        <td>A proof-of-concept script to conduct a phishing attack abusing Microsoft 365 OAuth Authorization Flow</td>
    </tr>
    <tr>
        <td><a href="https://pretext-project.github.io/">Pretext Project</a></td>
        <td>Open-Source Collection of Social Engineering Pretexts</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Raikia/UhOh365">Raikia/UhOh365</a></td>
        <td> A script that can see if an email address is valid in Office365 (user/email enumeration). This does not perform any login attempts, is unthrottled, and is incredibly useful for social engineering assessments to find which emails exist and which don't. </td>
    </tr>
    <tr>
        <td><a href="https://github.com/ralphte/build_a_phish">ralphte/build_a_phish</a></td>
        <td>Ansible playbook to deploy a phishing engagement in the cloud.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Rices/Phishious">Rices/Phishious</a></td>
        <td>An open-source Secure Email Gateway (SEG) evaluation toolkit designed for red-teamers.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ring0lab/catphish">ring0lab/catphish</a></td>
        <td>Generate similar-looking domains for phishing attacks. Check expired domains and their categorized domain status to evade proxy categorization. Whitelisted domains are perfect for your C2 servers.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/sebastian-mora/awsssome_phish">sebastian-mora/awsssome_phish</a></td>
        <td>AWS SSO serverless phishing API.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/securestate/king-phisher/">securestate/king-phisher</a></td>
        <td>Phishing Campaign Toolkit</td>
    </tr>
    <tr>
        <td><a href="https://github.com/secureworks/PhishInSuits">secureworks/PhishInSuits</a></td>
        <td>PhishInSuits: OAuth Device Code Phishing with Verified Apps</td>
    </tr>
    <tr>
        <td><a href="https://github.com/threatexpress/domainhunter">threatexpress/domainhunter</a></td>
        <td>Checks expired domains for categorization/reputation and Archive.org history to determine good candidates for phishing and C2 domain names</td>
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
    <tr>
        <td><a href="https://github.com/xiecat/goblin">xiecat/goblin</a></td>
        <td>Goblin for Phishing Exercise Tools</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Yaxser/SharpPhish">Yaxser/SharpPhish</a></td>
        <td>Using outlook COM objects to create convincing phishing emails without the user noticing. This project is meant for internal phishing.</td>
    </tr>
</table>

## Smart Contract

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
    <tr>
        <td><a href="https://www.breadcrumbs.app/">breadcrumbs</a></td>
        <td>Breadcrumbs is a blockchain analytics platform accessible to everyone. It offers a range of tools for investigating, monitoring, tracking and sharing relevant information on blockchain transactions.</td>
    </tr>
    <tr>
        <td><a href="https://capturetheether.com/">Capture the Ether</a></td>
        <td>THE GAME OF ETHEREUM SMART CONTRACT SECURITY</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cleanunicorn/karl">cleanunicorn/karl</a></td>
        <td>Monitor smart contracts deployed on blockchain and test against vulnerabilities with Mythril</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ConsenSys/mythril">ConsenSys/mythril</a></td>
        <td>Security analysis tool for EVM bytecode. Supports smart contracts built for Ethereum, Hedera, Quorum, Vechain, Roostock, Tron and other EVM-compatible blockchains.</td>
    </tr>
    <tr>
        <td><a href="https://contract-library.com/">Contract list</a></td>
        <td>Ethereum Contract Library by Dedaub</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ConsenSys/smart-contract-best-practices">ConsenSys/smart-contract-best-practices</a></td>
        <td>A guide to smart contract security best practices</td>
    </tr>
    <tr>
        <td><a href="https://github.com/crytic/echidna">crytic/echidna</a></td>
        <td>Ethereum smart contract fuzzer</td>
    </tr>
    <tr>
        <td><a href="https://github.com/csienslab/ProMutator">csienslab/ProMutator</a></td>
        <td>ProMutator: Detecting Vulnerable Price Oracles in DeFi by Mutated Transactions</td>
    </tr>
    <tr>
        <td><a href="https://github.com/crytic/slither">crytic/slither</a></td>
        <td>Static Analyzer for Solidity</td>
    </tr>
    <tr>
        <td><a href="https://www.damnvulnerabledefi.xyz/">Damn Vulnerable DeFi</a></td>
        <td>Damn Vulnerable DeFi is the wargame to learn offensive security of DeFi smart contracts.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ethereum-lists/contracts">ethereum-lists/contracts</a></td>
        <td>List of contracts from known projects (work in progress)</td>
    </tr>
    <tr>
        <td><a href="https://ethtx.info/">EthTx Transaction Decoder</a></td>
        <td>EthTx is an open source decoder of blockchain transactions that is made freely available to the Ethereum Community as a Python library in public PyPi index</td>
    </tr>
    <tr>
        <td><a href="https://github.com/enzymefinance/oyente">enzymefinance/oyente</a></td>
        <td>An Analysis Tool for Smart Contracts</td>
    </tr>
    <tr>
        <td><a href="https://eth.build/">ETH.Build</a></td>
        <td>An Educational Sandbox For Web3... And Much More.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/fravoll/solidity-patterns">fravoll/solidity-patterns</a></td>
        <td>A compilation of patterns and best practices for the smart contract programming language Solidity</td>
    </tr>
    <tr>
        <td><a href="https://github.com/IC3Hydra/Hydra">IC3Hydra/Hydra</a></td>
        <td>Framework for cryptoeconomic contract security, decentralized security bounties. Live on Ethereum.</td>
    </tr>
    <tr>
        <td><a href="https://lossless.cash/">Lossless</a></td>
        <td>The first DeFi hack mitigation tool for token creators.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mikedeshazer/bricks">mikedeshazer/bricks</a></td>
        <td>Bricks is a sandbox and instruction manual collection for building smart contract exploits for Ethereum blockchains, designed to help developers think like hackers in a safe, fun environment.</td>
    </tr>
    <tr>
        <td><a href="https://mythx.io/">Mytx</a></td>
        <td>Smart contract security service for Ethereum</td>
    </tr>
    <tr>
        <td><a href="https://github.com/nascentxyz/pyrometer">nascentxyz/pyrometer</a></td>
        <td>A tool for analyzing the security and parameters of a solidity smart contract</td>
    </tr>
    <tr>
        <td><a href="https://github.com/nccgroup/GOATCasino">nccgroup/GOATCasino</a></td>
        <td>This is an intentionally vulnerable smart contract truffle deployment aimed at allowing those interested in smart contract security to exploit a wide variety of issues in a safe environment.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/OpenZeppelin/contracts-wizard">OpenZeppelin/contracts-wizard</a></td>
        <td>Interactive smart contract generator based on OpenZeppelin Contracts.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/OpenZeppelin/damn-vulnerable-defi">OpenZeppelin/damn-vulnerable-defi</a></td>
        <td>A set of challenges to hack implementations of DeFi in Ethereum. Featuring flash loans, oracles, governance, NFTs, lending pools, and more!</td>
    </tr>
    <tr>
        <td><a href="https://phalcon.blocksec.com/">Phalcon</a></td>
        <td>Powerful Transaction Explorer Designed For DeFi Community</td>
    </tr>
    <tr>
        <td><a href="https://github.com/raineorshine/solgraph">raineorshine/solgraph</a></td>
        <td>Visualize Solidity control flow for smart contract security analysis. 💵 ⇆ 💵</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Raz0r/semgrep-smart-contracts">Raz0r/semgrep-smart-contracts</a></td>
        <td>Semgrep rules for smart contracts based on DeFi exploits</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Robsonsjre/FlashloanUsecases">Robsonsjre/FlashloanUsecases</a></td>
        <td>DeFi 201 - Lets hack Flash Loans</td>
    </tr>
    <tr>
        <td><a href="https://github.com/sigp/beacon-fuzz">sigp/beacon-fuzz</a></td>
        <td>Differential Fuzzer for Ethereum 2.0</td>
    </tr>
    <tr>
        <td><a href="https://github.com/smartbugs/smartbugs">smartbugs/smartbugs</a></td>
        <td>SmartBugs: A Framework to Analyze Solidity Smart Contracts</td>
    </tr>
    <tr>
        <td><a href="https://github.com/SunWeb3Sec/DeFiHackLabs">SunWeb3Sec/DeFiHackLabs</a></td>
        <td>Reproduce DeFi hack incidents using Foundry.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/SunWeb3Sec/DeFiVulnLabs">SunWeb3Sec/DeFiVulnLabs</a></td>
        <td>To learn common smart contract vulnerabilities using Foundry!</td>
    </tr>
    <tr>
        <td><a href="https://ethernaut.openzeppelin.com/">The Ethernaut</a></td>
        <td>The Ethernaut is a Web3/Solidity based wargame inspired on overthewire.org, played in the Ethereum Virtual Machine. Each level is a smart contract that needs to be 'hacked'.</td>
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
        <td><a href="https://github.com/atxsinn3r/VulnCases">atxsinn3r/VulnCases</a></td>
        <td>Vulnerability examples.</td>
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
        <td><a href="https://github.com/Azure/SimuLand">Azure/SimuLand</a></td>
        <td>Understand adversary tradecraft and improve detection strategies</td>
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
        <td><a href="https://github.com/brant-ruan/metarget">brant-ruan/metarget</a></td>
        <td>Framework providing automatic constructions of vulnerable infrastructures</td>
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
        <td><a href="https://github.com/CodeShield-Security/Serverless-Goat-Java">CodeShield-Security/Serverless-Goat-Java</a></td>
        <td>Java version of the deliberately vulnerable serverless application Serverless-Goat from https://github.com/OWASP/Serverless-Goat</td>
    </tr>
    <tr>
        <td><a href="https://github.com/detectify/vulnerable-nginx">detectify/vulnerable-nginx</a></td>
        <td>An intentionally vulnerable NGINX setup</td>
    </tr>
    <tr>
        <td><a href="https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application">dolevf/Damn-Vulnerable-GraphQL-Application</a></td>
        <td>Damn Vulnerable GraphQL Application is an intentionally vulnerable implementation of Facebook's GraphQL technology, to learn and practice GraphQL Security.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Flangvik/DeployPrinterNightmare">Flangvik/DeployPrinterNightmare</a></td>
        <td>C# tool for installing a shared network printer abusing the PrinterNightmare bug to allow other network machines easy privesc!</td>
    </tr>
    <tr>
        <td><a href="https//github.com/globocom/secDevLabs">globocom/secDevLabs</a></td>
        <td>A laboratory for learning secure web and mobile development in a practical manner.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/google/google-ctf">google/google-ctf</a></td>
        <td>This repository lists most of the challenges used in the Google CTF 2017. The missing challenges are not ready to be open-sourced, or contain third-party code.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/GoSecure/pyrdp">GoSecure/pyrdp</a></td>
        <td>RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact</td>
    </tr>
    <tr>
        <td><a href="https://github.com/kmcquade/owasp-youtube-2021">kmcquade/owasp-youtube-2021</a></td>
        <td>Deliberately vulnerable AWS resources for security assessment demos</td>
    </tr>
    <tr>
        <td><a href="https://tuts4you.com/download.php?list.17">Lenas Reversing for Newbies</a></td>
        <td>Nice collection of tutorials aimed particularly for newbie reverse enginners...</td>
    </tr>
    <tr>
        <td><a href="https://github.com/InsiderPhD/Generic-University">InsiderPhD/Generic-University</a></td>
        <td>Vulnerable API</td>
    </tr>
    <tr>
        <td><a href="https://github.com/madhuakula/kubernetes-goat">madhuakula/kubernetes-goat</a></td>
        <td>Kubernetes Goat is "Vulnerable by Design" Kubernetes Cluster. Designed to be an intentionally vulnerable cluster environment to learn and practice Kubernetes security.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mandiant/Azure_Workshop">mandiant/Azure_Workshop</a></td>
        <td>Azure Red Team Attack and Detect Workshop</td>
    </tr>
    <tr>
        <td><a href="https://github.com/nccgroup/sadcloud">nccgroup/sadcloud</a></td>
        <td>A tool for standing up (and tearing down!) purposefully insecure cloud infrastructure</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Orange-Cyberdefense/GOAD">Orange-Cyberdefense/GOAD</a></td>
        <td>GOAD is a pentest active directory LAB project. The purpose of this lab is to give pentesters a vulnerable Active directory environement ready to use to practice usual attack techniques.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/OWASP/iGoat-Swift">OWASP/iGoat-Swift</a></td>
        <td>OWASP iGoat (Swift) - A Damn Vulnerable Swift Application for iOS</td>
    </tr>
    <tr>
        <td><a href="https://github.com/quarkslab/minik8s-ctf">quarkslab/minik8s-ctf</a></td>
        <td>A beginner-friendly CTF about Kubernetes security.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/rapid7/hackazon">rapid7/hackazon</a></td>
        <td>A modern vulnerable web app</td>
    </tr>
    <tr>
        <td><a href="https://github.com/rewanth1997/Damn-Vulnerable-Bank">rewanth1997/Damn-Vulnerable-Bank</a></td>
        <td>Vulnerable Banking Application for Android</td>
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
        <td><a href="https://github.com/shellphish/how2heap">shellphish/how2heap</a></td>
        <td>A repository for learning various heap exploitation techniques.</td>
    </tr>
    <tr>
        <td><a href="https://www.notsosecure.com/vulnerable-docker-vm/">Vulnerable Docker VM</a></td>
        <td>Ever fantasized about playing with docker misconfigurations, privilege escalation, etc. within a container?</td>
    </tr>
    <tr>
        <td><a href="https//github.com/vulhub/vulhub">vulhub/vulhub</a></td>
        <td>Pre-Built Vulnerable Environments Based on Docker-Compose</td>
    </tr>
    <tr>
        <td><a href="https://github.com/WazeHell/vulnerable-AD">WazeHell/vulnerable-AD</a></td>
        <td>Create a vulnerable active directory that's allowing you to test most of the active directory attacks in a local lab</td>
    </tr>
</table>
