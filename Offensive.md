# Offensive Bookmark <!-- omit in toc -->

<p align="center">
  <img src="cover.png">
</p>

<p align="center"><img src="https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg" /> <a href="https://github.com/pe3zx/my-infosec-awesome/actions"><img src="https://github.com/pe3zx/my-infosec-awesome/workflows/Ruby/badge.svg" /></a> <img src="https://img.shields.io/github/last-commit/pe3zx/my-infosec-awesome.svg"/> </p>

This page will contain my bookmark for offensive tools, briefly categorized based on [MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/). Some links and sections on [README.md](README.md) will be relocated to this page if it's related to offensive tactics and techniques.

- [Reconnaissance/Discovery](#reconnaissancediscovery)
- [Execution](#execution)
  - [Living Off The Land](#living-off-the-land)
  - [Manipulating Binary's Internal](#manipulating-binarys-internal)
  - [Payload Generation](#payload-generation)
- [Persistence](#persistence)
- [Privilege Escalation](#privilege-escalation)
- [Defense Evasion](#defense-evasion)
- [Credential Access](#credential-access)
- [Lateral Movement](#lateral-movement)
- [Command & Control](#command--control)
- [Exfiltration](#exfiltration)

## Reconnaissance/Discovery

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/dev-2null/adcollector">dev-2null/ADCollector<a></td>
        <td>A lightweight tool to quickly extract valuable information from the Active Directory environment for both attacking and defending.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/dirkjanm/ROADtools">dirkjanm/ROADtools</a></td>
        <td>The Azure AD exploration framework.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/GhostPack/Seatbelt">GhostPack/Seatbelt</a></td>
        <td>Seatbelt is a C# project that performs a number of security oriented host-survey "safety checks" relevant from both offensive and defensive security perspectives.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/jaredhaight/scout">jaredhaight/scout</a></td>
        <td>A .NET assembly for performing recon against hosts on a network</td>
    </tr>
    <tr>
        <td><a href="https://github.com/NetSPI/goddi">NetSPI/goddi</a></td>
        <td>goddi (go dump domain info) dumps Active Directory domain information</td>
    </tr>
    <tr>
        <td><a href="https://github.com/outflanknl/Recon-AD">outflanknl/Recon-AD</a></td>
        <td>Recon-AD, an AD recon tool based on ADSI and reflective DLL’s</td>
    </tr>
    <tr>
        <td><a href="https://github.com/rasta-mouse/Watson">rasta-mouse/Watson</a></td>
        <td>Enumerate missing KBs and suggest exploits for useful Privilege Escalation vulnerabilitiesEnumerate missing KBs and suggest exploits for useful Privilege Escalation vulnerabilities</td>
    </tr>
    <tr>
        <td><a href="https://github.com/sud0woodo/DCOMrade">sud0woodo/DCOMrade</a></td>
        <td>Powershell script for enumerating vulnerable DCOM Applications</td>
    </tr>
    <tr>
        <td><a href="https://github.com/TonyPhipps/Meerkat">TonyPhipps/Meerkat</a></td>
        <td>A collection of PowerShell modules designed for artifact gathering and reconnaisance of Windows-based endpoints.</td>
    </tr>
</table>

## Execution

### Living Off The Land

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/api0cradle/LOLBAS">api0cradle/LOLBAS</a></td>
        <td>Living Off The Land Binaries and Scripts (and now also Libraries)</td>
    </tr>
    <tr>
        <td><a href="https://github.com/bohops/GhostBuild">bohops/GhostBuild</a></td>
        <td>GhostBuild is a collection of simple MSBuild launchers for various GhostPack/.NET projects</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Cn33liz/p0wnedShell">Cn33liz/p0wnedShell</a></td>
        <td>p0wnedShell is an offensive PowerShell host application written in C# that does not rely on powershell.exe but runs powershell commands and functions within a powershell runspace environment (.NET)</td>
    </tr>
    <tr>
        <td><a href="https://github.com/FuzzySecurity/PowerShell-Suite">FuzzySecurity/PowerShell-Suite</a></td>
        <td>There are great tools and resources online to accomplish most any task in PowerShell, sometimes however, there is a need to script together a util for a specific purpose or to bridge an ontological gap. This is a collection of PowerShell utilities I put together either for fun or because I had a narrow application in mind.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/nccgroup/GTFOBLookup">nccgroup/GTFOBLookup</a></td>
        <td>Offline command line lookup utility for GTFOBins</td>
    </tr>
</table>

### Manipulating Binary's Internal

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/Cybellum/DoubleAgent">Cybellum/DoubleAgent</a></td>
        <td>DoubleAgent is a new Zero-Day technique for injecting code and maintaining persistence on a machine (i.e. auto-run).</td>
    </tr>
    <tr>
        <td><a href="https://github.com/jonatan1024/clrinject">jonatan1024/clrinject</a></td>
        <td>Injects C# EXE or DLL Assembly into every CLR runtime and AppDomain of another process.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/monoxgas/sRDI">monoxgas/sRDI</a></td>
        <td>Shellcode implementation of Reflective DLL Injection. Convert DLLs to position independent shellcode</td>
    </tr>
    <tr>
        <td><a href="https://github.com/stephenfewer/ReflectiveDLLInjection">stephenfewer/ReflectiveDLLInjection</a></td>
        <td>Reflective DLL injection is a library injection technique in which the concept of reflective programming is employed to perform the loading of a library from memory into a host process</td>
    </tr>
    <tr>
        <td><a href="https://github.com/slyd0g/UrbanBishopLocal">slyd0g/UrbanBishopLocal</a></td>
        <td>A port of FuzzySecurity's UrbanBishop project for inline shellcode execution. The execution vector uses a delegate vs an APC on a suspended threat at ntdll!RtlExitUserThread in UrbanBishop</td>
    </tr>
</table>

### Payload Generation

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/BC-SECURITY/Empire/">BC-SECURITY/Empire</a></td>
        <td>Empire is a PowerShell and Python post-exploitation agent.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mdsecactivebreach/SharpShooter">mdsecactivebreach/SharpShooter</a></td>
        <td>SharpShooter is a payload creation framework for the retrieval and execution of arbitrary CSharp source code.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Plazmaz/LNKUp">Plazmaz/LNKUp</a></td>
        <td>Generates malicious LNK file payloads for data exfiltration</td>
    </tr>
    <tr>
        <td><a href="https://github.com/sevagas/macro_pack">sevagas/macro_pack</a></td>
        <td>macro_pack is a tool used to automatize obfuscation and generation of MS Office documents for pentest, demo, and social engineering assessments. The goal of macro_pack is to simplify antimalware bypass and automatize the process from vba generation to final Office document generation.</td>
    </tr>
    <tr>
        <td><a href="https//github.com/trustedsec/unicorn">trustedsec/unicorn</a></td>
        <td>Unicorn is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory. Based on Matthew Graeber's powershell attacks and the powershell bypass technique presented by David Kennedy (TrustedSec) and Josh Kelly at Defcon 18.</td>
    </tr>
</table>

## Persistence

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/fireeye/SharPersist">fireeye/SharPersist</a></td>
        <td>Windows persistence toolkit written in C#.</td>
    </tr>
</table>

## Privilege Escalation

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/0xbadjuju/Tokenvator">0xbadjuju/Tokenvator</a></td>
        <td>A tool to elevate privilege with Windows Tokens</td>
    </tr>
    <tr>
        <td><a href="https://github.com/411Hall/JAWS">411Hall/JAWS</a></td>
        <td>JAWS is PowerShell script designed to help penetration testers (and CTFers) quickly identify potential privilege escalation vectors on Windows systems. It is written using PowerShell 2.0 so 'should' run on every Windows version since Windows 7.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/hlldz/dazzleUP">hlldz/dazzleUP</a></td>
        <td>A tool that detects the privilege escalation vulnerabilities caused by misconfigurations and missing updates in the Windows operating systems.</td>
    </tr>
</table>

## Defense Evasion

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/api0cradle/UltimateAppLockerByPassList">api0cradle/UltimateAppLockerByPassList</a></td>
        <td>The goal of this repository is to document the most common techniques to bypass AppLocker.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/danielbohannon/Invoke-DOSfuscation">danielbohannon/Invoke-DOSfuscation</a></td>
        <td>Cmd.exe Command Obfuscation Generator & Detection Test Harness</td>
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
        <td><a href="https://github.com/mdsecactivebreach/Chameleon">mdsecactivebreach/Chameleon</a></td>
        <td>Chameleon: A tool for evading Proxy categorisation</td>
    </tr>
    <tr>
        <td><a href="https://github.com/nccgroup/demiguise">nccgroup/demiguise</a></td>
        <td>HTA encryption tool for RedTeams</td>
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
        <td><a href="https://github.com/secretsquirrel/SigThief">secretsquirrel/SigThief</a></td>
        <td>Stealing Signatures and Making One Invalid Signature at a Time</td>
    </tr>
</table>

## Credential Access

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
    <tr>
		<td><a href="https://github.com/Arvanaghi/SessionGopher">Arvanaghi/SessionGopher</a></td>
		<td>SessionGopher is a PowerShell tool that uses WMI to extract saved session information for remote access tools such as WinSCP, PuTTY, SuperPuTTY, FileZilla, and Microsoft Remote Desktop. It can be run remotely or locally.</td>
	</tr>
    <tr>
        <td><a href="https://github.com/DanMcInerney/icebreaker">DanMcInerney/icebreaker</a></td>
        <td>Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment</td>
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
        <td><a href="https://github.com/Kevin-Robertson/Inveigh">Kevin-Robertson/Inveigh</td>
        <td>Windows PowerShell ADIDNS/LLMNR/mDNS/NBNS spoofer/man-in-the-middle tool</td>
    </tr>
    <tr>
        <td><a href="https://github.com/nidem/kerberoast">nidem/kerberoast</a></td>
        <td>Kerberoast is a series of tools for attacking MS Kerberos implementations. Below is a brief overview of what each tool does.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/peewpw/Invoke-WCMDump">peewpw/Invoke-WCMDump</a></td>
        <td>PowerShell Script to Dump Windows Credentials from the Credential Manager</td>
    </tr>
    <tr>
        <td><a href="https://github.com/putterpanda/mimikittenz">putterpanda/mimikittenz</a></td>
        <td>A post-exploitation powershell tool for extracting juicy info from memory.</td>
    </tr>
</table>

## Lateral Movement

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/byt3bl33d3r/CrackMapExec">byt3bl33d3r/CrackMapExec</a></td>
        <td>A swiss army knife for pentesting networks</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cobbr/SharpSploit">cobbr/SharpSploit</a></td>
        <td>SharpSploit is a .NET post-exploitation library written in C#</td>
    </tr>
    <tr>
        <td><a href="https://github.com/DefensiveOrigins/PlumHound">DefensiveOrigins/PlumHound</a></td>
        <td>Bloodhound for Blue and Purple Teams</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ScorpionesLabs/DVS">ScorpionesLabs/DVS</a></td>
        <td>D(COM) V(ulnerability) S(canner) AKA Devious swiss army knife - Lateral movement using DCOM Objects</td>
    </tr>
</table>

## Command & Control

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/3xpl01tc0d3r/Callidus">3xpl01tc0d3r/Callidus</a></td>
        <td>It is developed using .net core framework in C# language. Allows operators to leverage O365 services for establishing command & control communication channel. It usages Microsoft Graph APIs for communicating with O365 services.</td>
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
        <td><a href="https://github.com/fbkcs/ThunderDNS">fbkcs/ThunderDNS</a></td>
        <td>This tool can forward TCP traffic over DNS protocol. Non-compile clients + socks5 support.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Ne0nd0g/merlin">Ne0nd0g/merlin</a></td>
        <td>Merlin is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in golang.</td>
    </tr>
    <tr>
        <td><a href="http://prismatica.io/">Project Prismatica</a></td>
        <td>Project Prismatica is a focused framework for Command and Control that is dedicated to extensibility.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/sensepost/godoh">sensepost/goDoH</a></td>
        <td>godoh - A DNS-over-HTTPS C2</td>
    </tr>
    <tr>
        <td><a href="https://github.com/SpiderLabs/DoHC2">SpiderLabs/DoHC2</a></td>
        <td>DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be leveraged for command and control (C2) via DNS over HTTPS (DoH).</td>
    </tr>
</table>

## Exfiltration

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
        <td><a href="https://github.com/hackerschoice/gsocket">hackerschoice/gsockethackerschoice/gsocket</a></td>
        <td>Global Socket. Moving data from here to there. Securely, Fast and trough NAT/Firewalls</td>
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
    <tr>
        <td><a href="https://github.com/vp777/procrustes">vp777/procrustes</a></td>
        <td>A bash script that automates the exfiltration of data over dns in case we have a blind command execution on a server where all outbound connections except DNS are blocked.</td>
    </tr>
</table>
