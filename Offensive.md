# Offensive Bookmark <!-- omit in toc -->

<p align="center">
  <img src="cover.png">
</p>

<p align="center"><img src="https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg" /> <a href="https://github.com/pe3zx/my-infosec-awesome/actions"><img src="https://github.com/pe3zx/my-infosec-awesome/workflows/Ruby/badge.svg" /></a> <img src="https://img.shields.io/github/last-commit/pe3zx/my-infosec-awesome.svg"/> </p>

This page will contain my bookmark for offensive tools, briefly categorized based on [MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/). Some links and sections on [README.md](README.md) will be relocated to this page if it's related to offensive tactics and techniques.

Some tools can be categorized in more than one category. But because the current bookmark model doesn't support 1-to-many mapping, I will decide a tool's category based on its ultimate goal.

- [Reconnaissance/Discovery](#reconnaissancediscovery)
- [Execution](#execution)
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
        <td><a href="https://github.com/danielbohannon/Invoke-CradleCrafter">danielbohannon/Invoke-CradleCrafter</a></td>
        <td>PowerShell Remote Download Cradle Generator & Obfuscator</td>
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
        <td><a href="https://github.com/djhohnstein/SharpShares">djhohnstein/SharpShares</a></td>
        <td>Enumerate all network shares in the current domain. Also, can resolve names to IP addresses.</td>
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
        <td><a href="https://github.com/mdsecactivebreach/sitrep">mdsecactivebreach/sitrep</a></td>
        <td>SitRep is intended to provide a lightweight, extensible host triage alternative.</td>
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
        <td><a href="https://github.com/stufus/reconerator">stufus/reconerator</a></td>
        <td>C# Targeted Attack Reconnissance Tools</td>
    </tr>
    <tr>
        <td><a href="https://github.com/sud0woodo/DCOMrade">sud0woodo/DCOMrade</a></td>
        <td>Powershell script for enumerating vulnerable DCOM Applications</td>
    </tr>
    <tr>
        <td><a href="https://github.com/tevora-threat/SharpView">tevora-threat/SharpView</a></td>
        <td>C# implementation of harmj0y's PowerView</td>
    </tr>
    <tr>
        <td><a href="https://github.com/TonyPhipps/Meerkat">TonyPhipps/Meerkat</a></td>
        <td>A collection of PowerShell modules designed for artifact gathering and reconnaisance of Windows-based endpoints.</td>
    </tr>
</table>

## Execution

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
        <td><a href="https://github.com/cobbr/SharpSploit">cobbr/SharpSploit</a></td>
        <td>SharpSploit is a .NET post-exploitation library written in C#</td>
    </tr>
    <tr>
        <td><a href="https://github.com/checkymander/Zolom">checkymander/Zolom</a></td>
        <td>C# Executable with embedded Python that can be used reflectively to run python code on systems without Python installed</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Cn33liz/p0wnedShell">Cn33liz/p0wnedShell</a></td>
        <td>p0wnedShell is an offensive PowerShell host application written in C# that does not rely on powershell.exe but runs powershell commands and functions within a powershell runspace environment (.NET)</td>
    </tr>
    <tr>
        <td><a href="https://github.com/D00MFist/Go4aRun">D00MFist/Go4aRun</a></td>
        <td>Shellcode runner in GO that incorporates shellcode encryption, remote process injection, block dlls, and spoofed parent process</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Flangvik/SharpCollection">Flangvik/SharpCollection</a></td>
        <td>Nightly builds of common C# offensive tools, fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.</td>
    </tr>
   <tr>
        <td><a href="https://github.com/FuzzySecurity/PowerShell-Suite">FuzzySecurity/PowerShell-Suite</a></td>
        <td>There are great tools and resources online to accomplish most any task in PowerShell, sometimes however, there is a need to script together a util for a specific purpose or to bridge an ontological gap. This is a collection of PowerShell utilities I put together either for fun or because I had a narrow application in mind.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/GhostPack/SharpWMI">GhostPack/SharpWMI</a></td>
        <td>SharpWMI is a C# implementation of various WMI functionality.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/hausec/MaliciousClickOnceMSBuild">hausec/MaliciousClickOnceMSBuild</a></td>
        <td>Basic C# Project that will take an MSBuild payload and run it with MSBuild via ClickOnce.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/jhalon/SharpCall">jhalon/SharpCall</a></td>
        <td>Simple PoC demonstrating syscall execution in C#</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mgeeky/Stracciatella">mgeeky/Stracciatella</a></td>
        <td>OpSec-safe Powershell runspace from within C# (aka SharpPick) with AMSI, Constrained Language Mode and Script Block Logging disabled at startup</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Mr-Un1k0d3r/RedTeamCSharpScripts">Mr-Un1k0d3r/RedTeamCSharpScripts</a></td>
        <td>C# Script used for Red Team. These binaries can be used by Cobalt Strike execute-assembly or as standalone executable.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/nccgroup/GTFOBLookup">nccgroup/GTFOBLookup</a></td>
        <td>Offline command line lookup utility for GTFOBins</td>
    </tr>
    <tr>
        <td><a href="https://github.com/NYAN-x-CAT/Csharp-Loader">NYAN-x-CAT/Csharp-Loader</a></td>
        <td>Download a .NET payload and run it on memory</td>
    </tr>
    <tr>
        <td><a href="https://github.com/rasta-mouse/MiscTools">rasta-mouse/MiscTools</a></td>
        <td>Miscellaneous Tools</td>
    </tr>
    <tr>
        <td><a href="https://gist.github.com/ropnop/fdd4e4ab537821eee5a1a751c044924f">ropnop/go-sharp-loader.go</a></td>
        <td>Example Go program with multiple .NET Binaries embedded</td>
    </tr>
    <tr>
        <td><a href="https://github.com/sh4hin/GoPurple">sh4hin/GoPurple</a></td>
        <td>Yet another shellcode runner consists of different techniques for evaluating detection capabilities of endpoint security solutions</td>
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
        <td><a href="https://github.com/Flangvik/SharpDllProxy">Flangvik/SharpDllProxy</a></td>
        <td>Retrieves exported functions from a legitimate DLL and generates a proxy DLL source code/template for DLL proxy loading or sideloading</td>
    </tr>
    <tr>
        <td><a href="https://github.com/forrest-orr/phantom-dll-hollower-poc">/forrest-orr/phantom-dll-hollower-poc</a></td>
        <td>Phantom DLL hollowing PoC</td>
    </tr>
    <tr>
        <td><a href="https://github.com/GoodstudyChina/APC-injection-x86-x64">GoodstudyChina/APC-injection-x86-x64</a></td>
        <td>injdrv is a proof-of-concept Windows Driver for injecting DLL into user-mode processes using APC.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/jonatan1024/clrinject">jonatan1024/clrinject</a></td>
        <td>Injects C# EXE or DLL Assembly into every CLR runtime and AppDomain of another process.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/jthuraisamy/SysWhispers">jthuraisamy/SysWhispers</a></td>
        <td>SysWhispers helps with evasion by generating header/ASM files implants can use to make direct system calls.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mobdk/Sigma">mobdk/Sigma</a></td>
        <td>Execute shellcode with ZwCreateSection, ZwMapViewOfSection, ZwOpenProcess, ZwMapViewOfSection and ZwCreateThreadEx</td>
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
    <tr>
        <td><a href="https://github.com/r3nhat/XORedReflectiveDLL">r3nhat/XORedReflectiveDLL</a></td>
        <td>Reflective DLL Injection with obfuscated (XOR) shellcode</td>
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
        <td><a href="https://github.com/Binject/backdoorfactory">Binject/backdoorfactory</a></td>
        <td>A from-scratch rewrite of The Backdoor Factory - a MitM tool for inserting shellcode into all types of binaries on the wire.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/BishopFox/sliver">BishopFox/sliver</a></td>
        <td>Sliver is a general purpose cross-platform implant framework that supports C2 over Mutual-TLS, HTTP(S), and DNS. Implants are dynamically compiled with unique X.509 certificates signed by a per-instance certificate authority generated when you first run the binary.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cedowens/Mythic-Macro-Generator">cedowens/Mythic-Macro-Generator</a></td>
        <td>Python3 script to generate a macro to launch a Mythic payload. Author: Cedric Owens</td>
    </tr>
    <tr>
        <td><a href="https://github.com/damienvanrobaeys/PS1-To-EXE-Generator">damienvanrobaeys/PS1-To-EXE-Generator</a></td>
        <td>PS1 to EXE Generator: Create an EXE for your PS1 scripts</td>
    </tr>
    <tr>
        <td><a href="https://github.com/FortyNorthSecurity/EXCELntDonut">FortyNorthSecurity/EXCELntDonut</a></td>
        <td>Excel 4.0 (XLM) Macro Generator for injecting DLLs and EXEs into memory.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/FortyNorthSecurity/hot-manchego">FortyNorthSecurity/hot-manchego</a></td>
        <td>Macro-Enabled Excel File Generator (.xlsm) using the EPPlus Library.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/gen0cide/gscript">gen0cide/gscript</a></td>
        <td>framework to rapidly implement custom droppers for all three major operating systems</td>
    </tr>
    <tr>
        <td><a href="https://github.com/glinares/InlineShapesPayload">glinares/InlineShapesPayload</a></td>
        <td>VBA InlineShapes Payload Generator</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Greenwolf/ntlm_theft">Greenwolf/ntlm_theft</a></td>
        <td>A tool for generating multiple types of NTLMv2 hash theft files by Jacob Wilkin (Greenwolf)</td>
    </tr>
    <tr>
        <td><a href="https://github.com/infosecn1nja/MaliciousMacroMSBuild">infosecn1nja/MaliciousMacroMSBuild</a></td>
        <td>Generates Malicious Macro and Execute Powershell or Shellcode via MSBuild Application Whitelisting Bypass.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/l373/GIVINGSTORM">l373/GIVINGSTORM</a></td>
        <td>Infection vector that bypasses AV, IDS, and IPS. (For now...)</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mdsecactivebreach/SharpShooter">mdsecactivebreach/SharpShooter</a></td>
        <td>SharpShooter is a payload creation framework for the retrieval and execution of arbitrary CSharp source code.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/michaelweber/Macrome">michaelweber/Macrome</a></td>
        <td>Excel Macro Document Reader/Writer for Red Teamers & Analysts</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Mr-Un1k0d3r/MaliciousDLLGenerator">Mr-Un1k0d3r/MaliciousDLLGenerator</a></td>
        <td>DLL Generator for side loading attack</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Plazmaz/LNKUp">Plazmaz/LNKUp</a></td>
        <td>Generates malicious LNK file payloads for data exfiltration</td>
    </tr>
    <tr>
        <td><a href="https://github.com/redcanaryco/chain-reactor">redcanaryco/chain-reactor</a></td>
        <td>Chain Reactor is an open source framework for composing executables that simulate adversary behaviors and techniques on Linux endpoints.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/sevagas/macro_pack">sevagas/macro_pack</a></td>
        <td>macro_pack is a tool used to automatize obfuscation and generation of MS Office documents for pentest, demo, and social engineering assessments. The goal of macro_pack is to simplify antimalware bypass and automatize the process from vba generation to final Office document generation.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/TheWover/donut">TheWover/donut</a></td>
        <td>Generates x86, x64, or AMD64+x86 position-independent shellcode that loads .NET Assemblies, PE files, and other Windows payloads from memory and runs them with parameters</td>
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
        <td><a href="https://github.com/360-Linton-Lab/Telemetry">360-Linton-Lab/Telemetry</a></td>
        <td>TELEMETRY is a C# For Windows PERSISTENCE</td>
    </tr>
    <tr>
        <td><a href="https://github.com/airzero24/PortMonitorPersist">airzero24/PortMonitorPersist</a></td>
        <td>PoC for Port Monitor Persistence</td>
    </tr>
    <tr>
        <td><a href="https://github.com/fireeye/SharPersist">fireeye/SharPersist</a></td>
        <td>Windows persistence toolkit written in C#.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/panagioto/SyscallHide">panagioto/SyscallHide</a></td>
        <td>Create a Run registry key with direct system calls. Inspired by @Cneelis's Dumpert and SharpHide.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/slaeryan/MIDNIGHTTRAIN">slaeryan/MIDNIGHTTRAIN</a></td>
        <td>Covert Stage-3 Persistence Framework</td>
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
        <td><a href="https://github.com/antonioCoco/RogueWinRM">antonioCoco/RogueWinRM</a></td>
        <td>Windows Local Privilege Escalation from Service Account to System</td>
    </tr>
    <tr>
        <td><a href="https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite">carlospolop/privilege-escalation-awesome-scripts-suite</a></td>
        <td>PEASS - Privilege Escalation Awesome Scripts SUITE (with colors)</td>
    </tr>
    <tr>
        <td><a href="https://github.com/hlldz/dazzleUP">hlldz/dazzleUP</a></td>
        <td>A tool that detects the privilege escalation vulnerabilities caused by misconfigurations and missing updates in the Windows operating systems.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/itm4n/PrivescCheck">itm4n/PrivescCheck</a></td>
        <td>Privilege Escalation Enumeration Script for Windows</td>
    </tr>
    <tr>
        <td><a href="https://github.com/sailay1996/delete2SYSTEM">sailay1996/delete2SYSTEM</a></td>
        <td>Weaponizing for Arbitrary Files/Directories Delete bugs to Get NT AUTHORITY\SYSTEM</td>
    </tr>
</table>

## Defense Evasion

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/89luca89/pakkero">89luca89/pakkero</a></td>
        <td>Pakkero is a binary packer written in Go made for fun and educational purpose. Its main goal is to take in input a program file (elf binary, script, even appimage) and compress it, protect it from tampering and intrusion.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/api0cradle/UltimateAppLockerByPassList">api0cradle/UltimateAppLockerByPassList</a></td>
        <td>The goal of this repository is to document the most common techniques to bypass AppLocker.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/bohops/UltimateWDACBypassList">bohops/UltimateWDACBypassList</a></td>
        <td>A centralized resource for previously documented WDAC bypass techniques</td>
    </tr>
    <tr>
        <td><a href="https://github.com/br-sn/CheekyBlinder">br-sn/CheekyBlinder</a></td>
        <td>Enumerating and removing kernel callbacks using signed vulnerable drivers</td>
    </tr>
    <tr>
        <td><a href="https://github.com/CCob/SharpBlock">CCob/SharpBlock</a></td>
        <td>A method of bypassing EDR's active projection DLL's by preventing entry point execution.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cwolff411/powerob">cwolff411/powerob</a></td>
        <td>An on-the-fly Powershell script obfuscator meant for red team engagements. Built out of necessity.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/d00rt/ebfuscator">d00rt/ebfuscator</a></td>
        <td>Ebfuscator: Abusing system errors for binary obfuscation</td>
    </tr>
    <tr>
        <td><a href="https://github.com/d35ha/CallObfuscator">d35ha/CallObfuscator</a></td>
        <td>Obfuscate specific windows apis with different apis</td>
    </tr>
    <tr>
        <td><a href="https://github.com/danielbohannon/Invoke-DOSfuscation">danielbohannon/Invoke-DOSfuscation</a></td>
        <td>Cmd.exe Command Obfuscation Generator & Detection Test Harness</td>
    </tr>
    <tr>
        <td><a href="https://github.com/DarthTon/Polychaos">DarthTon/Polychaos</a></td>
        <td>PE permutation library</td>
    </tr>
    <tr>
        <td><a href="https://github.com/dsnezhkov/zombieant">dsnezhkov/zombieant</a></td>
        <td>Zombie Ant Farm: Primitives and Offensive Tooling for Linux EDR evasion.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/EgeBalci/Amber">EgeBalci/Amber</a></td>
        <td>amber is a reflective PE packer for bypassing security products and mitigations. It can pack regularly compiled PE files into reflective payloads that can load and execute itself like a shellcode.</td>
    </tr>
   <tr>
        <td><a href="https://github.com/ffuf/pencode">ffuf/pencode</a></td>
        <td>Complex payload encoder</td>
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
        <td><a href="https://github.com/jthuraisamy/TelemetrySourcerer">jthuraisamy/TelemetrySourcerer</a></td>
        <td>Enumerate and disable common sources of telemetry used by AV/EDR.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/matterpreter/DefenderCheck">matterpreter/DefenderCheck</a></td>
        <td>Identifies the bytes that Microsoft Defender flags on.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mdsecactivebreach/Chameleon">mdsecactivebreach/Chameleon</a></td>
        <td>Chameleon: A tool for evading Proxy categorisation</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mdsecactivebreach/firewalker">mdsecactivebreach/firewalker</a></td>
        <td>This repo contains a simple library which can be used to add FireWalker hook bypass capabilities to existing code</td>
    </tr>
    <tr>
        <td><a href="https://github.com/nccgroup/demiguise">nccgroup/demiguise</a></td>
        <td>HTA encryption tool for RedTeams</td>
    </tr>
    <tr>
        <td><a href="https://github.com/NotPrab/.NET-Obfuscator">NotPrab/.NET-Obfuscator</a></td>
        <td>Lists of .NET Obfuscator (Free, Trial, Paid and Open Source )</td>
    </tr>
    <tr>
        <td><a href="https://github.com/OmerYa/Invisi-Shell">OmerYa/Invisi-Shell</a></td>
        <td>Hide your Powershell script in plain sight. Bypass all Powershell security features</td>
    </tr>
    <tr>
        <td><a href="https://github.com/OsandaMalith/PE2HTML">OsandaMalith/PE2HTML</a></td>
        <td>Injects HTML/PHP/ASP to the PE</td>
    </tr>
    <tr>
        <td><a href="https://github.com/peewpw/Invoke-PSImage">peewpw/Invoke-PSImage</a></td>
        <td>Embeds a PowerShell script in the pixels of a PNG file and generates a oneliner to execute</td>
    </tr>
    <tr>
        <td><a href="https://github.com/PwnDexter/SharpEDRChecker">PwnDexter/SharpEDRChecker</a></td>
        <td>Checks running processes, process metadata, Dlls loaded into your current process and the each DLLs metadata, common install directories, installed services and each service binaries metadata, installed drivers and each drivers metadata, all for the presence of known defensive products such as AV's, EDR's and logging tools.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/secretsquirrel/SigThief">secretsquirrel/SigThief</a></td>
        <td>Stealing Signatures and Making One Invalid Signature at a Time</td>
    </tr>
    <tr>
        <td><a href="https://github.com/slyd0g/SharpCrashEventLog">slyd0g/SharpCrashEventLog</a></td>
        <td>C# port of LogServiceCrash</td>
    </tr>
    <tr>
        <td><a href="https://github.com/the-xentropy/xencrypt">the-xentropy/xencrypt</a></td>
        <td>A PowerShell script anti-virus evasion tool</td>
    </tr>
    <tr>
        <td><a href="https://github.com/tokyoneon/chimera">tokyoneon/chimera</a></td>
        <td>Chimera is a (shiny and very hack-ish) PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions.</td>
    </tr>
</table>

## Credential Access

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/aas-n/spraykatz">aas-n/spraykatz</a></td>
        <td>Credentials gathering tool automating remote procdump and parse of lsass process.</td>
    </tr>
    <tr>
		<td><a href="https://github.com/Arvanaghi/SessionGopher">Arvanaghi/SessionGopher</a></td>
		<td>SessionGopher is a PowerShell tool that uses WMI to extract saved session information for remote access tools such as WinSCP, PuTTY, SuperPuTTY, FileZilla, and Microsoft Remote Desktop. It can be run remotely or locally.</td>
	</tr>
    <tr>
        <td><a href="https://github.com/b4rtik/SharpKatz">b4rtik/SharpKatz</a></td>
        <td>Porting of mimikatz sekurlsa::logonpasswords, sekurlsa::ekeys and lsadump::dcsync commands</td>
    </tr>
    <tr>
        <td><a href="https://github.com/b4rtik/SharpMiniDump">b4rtik/SharpMiniDump</a></td>
        <td>Create a minidump of the LSASS process from memory</td>
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
        <td><a href="https://github.com/Flangvik/BetterSafetyKatz">Flangvik/BetterSafetyKatz</a></td>
        <td>Fork of SafetyKatz that dynamically fetches the latest pre-compiled release of Mimikatz directly from gentilkiwi GitHub repo, runtime patches signatures and uses SharpSploit DInvoke to PE-Load into memory.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/FSecureLABS/physmem2profit">FSecureLABS/physmem2profit </a></td>
        <td>Physmem2profit can be used to create a minidump of a target hosts' LSASS process by analysing physical memory remotely</td>
    </tr>
    <tr>
        <td><a href="https://github.com/G0ldenGunSec/SharpSecDump">G0ldenGunSec/SharpSecDump</a></td>
        <td>.Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py</td>
    </tr>
    <tr>
        <td><a href="https://github.com/GhostPack/SafetyKatz">GhostPack/SafetyKatz</a></td>
        <td>SafetyKatz is a combination of slightly modified version of @gentilkiwi's Mimikatz project and @subTee's .NET PE Loader</td>
    </tr>
    <tr>
        <td><a href="https://github.com/GhostPack/SharpDump">GhostPack/SharpDump</a></td>
        <td>SharpDump is a C# port of PowerSploit's Out-Minidump.ps1 functionality.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/GhostPack/Rubeus">GhostPack/Rubeus</a></td>
        <td>Rubeus is a C# toolset for raw Kerberos interaction and abusesRubeus is a C# toolset for raw Kerberos interaction and abuses</td>
    </tr>
    <tr>
        <td><a href="https://github.com/gitjdm/dumper2020">gitjdm/dumper2020</a></td>
        <td>Yet another LSASS dumper</td>
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
    <tr>
        <td><a href="https://github.com/skelsec/pypykatz">skelsec/pypykatz</a></td>
        <td>Mimikatz implementation in pure Python</td>
    </tr>
    <tr>
        <td><a href="https://github.com/SnaffCon/Snaffler">SnaffCon/Snaffler</a></td>
        <td>Snaffler is a tool for pentesters to help find delicious candy needles (creds mostly, but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment).</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Viralmaniar/Remote-Desktop-Caching-">Viralmaniar/Remote-Desktop-Caching-</a></td>
        <td>This tool allows one to recover old RDP (mstsc) session information in the form of broken PNG files. These PNG files allows Red Team member to extract juicy information such as LAPS passwords or any sensitive information on the screen.</td>
    </tr>
</table>

## Lateral Movement

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/360-Linton-Lab/WMIHACKER">360-Linton-Lab/WMIHACKER</a></td>
        <td>A Bypass Anti-virus Software Lateral Movement Command Execution Tool</td>
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
        <td><a href="https://github.com/Mr-Un1k0d3r/SCShell">Mr-Un1k0d3r/SCShell</a></td>
        <td>Fileless lateral movement tool that relies on ChangeServiceConfigA to run command</td>
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
