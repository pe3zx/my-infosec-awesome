# Offensive Bookmark <!-- omit in toc -->

<p align="center">
    <img src="cover.png">
</p>

<p align="center"><img src="https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg" /> <a href="https://github.com/pe3zx/my-infosec-awesome/actions"><img src="https://github.com/pe3zx/my-infosec-awesome/workflows/Ruby/badge.svg" /></a> <img src="https://img.shields.io/github/last-commit/pe3zx/my-infosec-awesome.svg" /> </p>

This page will contain my bookmark for offensive tools, briefly categorized based on [MITRE ATT&CK Enterprise
Matrix](https://attack.mitre.org/matrices/enterprise/). Some links and sections on [README.md](README.md) will be
relocated to this page if it's related to offensive tactics and techniques.

Some tools can be categorized in more than one category. But because the current bookmark model doesn't support
1-to-many mapping, I will decide a tool's category based on its ultimate goal.

- [Reconnaissance/Discovery](#reconnaissancediscovery)
- [Initial Access](#initial-access)
- [Execution](#execution)
    - [Manipulating Binary's Internal](#manipulating-binarys-internal)
    - [Payload Generation](#payload-generation)
- [Persistence](#persistence)
- [Privilege Escalation](#privilege-escalation)
- [Defense Evasion](#defense-evasion)
- [Credential Access](#credential-access)
- [Lateral Movement](#lateral-movement)
- [Collection](#collection)
- [Command & Control](#command--control)
- [Exfiltration](#exfiltration)

## Reconnaissance/Discovery

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/asaurusrex/Probatorum-EDR-Userland-Hook-Checker">asaurusrex/Probatorum-EDR-Userland-Hook-Checker</a>
        <td>Project to check which Nt/Zw functions your local EDR is hooking</td>
    </tr>
    <tr>
        <td><a href="https://github.com/boku7/whereami">boku7/whereami</a></td>
        <td>Cobalt Strike Beacon Object File (BOF) that uses handwritten shellcode to return the process Environment strings without touching any DLL's.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/chdav/SharpCGHunter">chdav/SharpCGHunter</a></td>
        <td>Receive the status of Windows Defender Credential Guard on network hosts.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/codingo/Reconnoitre">codingo/Reconnoitre</a></td>
        <td>A security tool for multithreaded information gathering and service enumeration whilst building directory structures to store results, along with writing out recommendations for further testing.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/dev-2null/adcollector">dev-2null/ADCollector<a></td>
        <td>A lightweight tool to quickly extract valuable information from the Active Directory environment for both
            attacking and defending.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/dirkjanm/ROADtools">dirkjanm/ROADtools</a></td>
        <td>The Azure AD exploration framework.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/djhohnstein/SharpSearch">djhohnstein/SharpSearch</a></td>
        <td>Search files for extensions as well as text within.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/djhohnstein/SharpShares">djhohnstein/SharpShares</a></td>
        <td>Enumerate all network shares in the current domain. Also, can resolve names to IP addresses.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/dsnezhkov/TruffleSnout">dsnezhkov/TruffleSnout</a></td>
        <td>Iterative AD discovery toolkit for offensive operations</td>
    </tr>
    <tr>
        <td><a href="https://github.com/EspressoCake/Process_Protection_Level_BOF">EspressoCake/Process_Protection_Level_BOF</a></td>
        <td>A Syscall-only BOF file intended to grab process protection attributes, limited to a handful that Red Team operators and pentesters would commonly be interested in.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/fashionproof/CheckSafeBoot">fashionproof/CheckSafeBoot</a></td>
        <td>I used this to see if an EDR is running in Safe Mode</td>
    </tr>
    <tr>
        <td><a href="https://github.com/GhostPack/Seatbelt">GhostPack/Seatbelt</a></td>
        <td>Seatbelt is a C# project that performs a number of security oriented host-survey "safety checks" relevant
            from both offensive and defensive security perspectives.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/jaredhaight/scout">jaredhaight/scout</a></td>
        <td>A .NET assembly for performing recon against hosts on a network</td>
    </tr>
    <tr>
        <td><a href="https://github.com/lkarlslund/adalanche">lkarlslund/adalanche</a></td>
        <td>Active Directory ACL Visualizer - who's really Domain Admin?</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mdsecactivebreach/sitrep">mdsecactivebreach/sitrep</a></td>
        <td>SitRep is intended to provide a lightweight, extensible host triage alternative.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mez-0/SharpShares">mez-0/SharpShares</a></td>
        <td>.NET 4.0 Share Hunting and ACL Mapping</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Mr-Un1k0d3r/ADHuntTool">Mr-Un1k0d3r/ADHuntTool</a></td>
        <td>official repo for the AdHuntTool (part of the old RedTeamCSharpScripts repo)</td>
    </tr>
    <tr>
        <td><a href="https://github.com/nccgroup/Carnivore">nccgroup/Carnivore</a></td>
        <td>Tool for assessing on-premises Microsoft servers authentication such as ADFS, Skype, Exchange, and RDWeb</td>
    </tr>
    <tr>
        <td><a href="https://github.com/NetSPI/goddi">NetSPI/goddi</a></td>
        <td>goddi (go dump domain info) dumps Active Directory domain information</td>
    </tr>
    <tr>
        <td><a href="https://github.com/optiv/Registry-Recon">optiv/Registry-Recon</a></td>
        <td>Cobalt Strike Aggressor Script that Performs System/AV/EDR Recon</td>
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
        <td><a href="https://github.com/rvrsh3ll/SharpPrinter">rvrsh3ll/SharpPrinter</a></td>
        <td>Discover Printers</td>
    </tr>
    <tr>
        <td><a href="https://github.com/s0lst1c3/SharpFinder">s0lst1c3/SharpFinder</a></td>
        <td>Description: Searches for files matching specific criteria on readable shares within the domain.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/S3cur3Th1sSh1t/Invoke-Sharpcradle">S3cur3Th1sSh1t/Invoke-Sharpcradle</a></td>
        <td>Load C# Code from a Webserver straight to memory and execute it there.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/sophoslabs/metasploit_gather_exchange">sophoslabs/metasploit_gather_exchange</a></td>
        <td>Metasploit Post-Exploitation Gather module for Exchange Server</td>
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
        <td><a href="https://github.com/T0pCyber/hawk">T0pCyber/hawk</a></td>
        <td>Powershell Based tool for gathering information related to O365 intrusions and potential Breaches</td>
    </tr>
    <tr>
        <td><a href="https://github.com/tasox/LogRM">tasox/LogRM</a></td>
        <td>LogRM is a post exploitation powershell script which it uses windows event logs to gather information about internal network</td>
    </tr>
    <tr>
        <td><a href="https://github.com/tevora-threat/SharpView">tevora-threat/SharpView</a></td>
        <td>C# implementation of harmj0y's PowerView</td>
    </tr>
    <tr>
        <td><a href="https://github.com/TonyPhipps/Meerkat">TonyPhipps/Meerkat</a></td>
        <td>A collection of PowerShell modules designed for artifact gathering and reconnaisance of Windows-based
            endpoints.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/tomcarver16/ADSearch">tomcarver16/ADSearch</a></td>
        <td>A tool to help query AD via the LDAP protocol</td>
    </tr>
    <tr>
        <td><a href="https://github.com/vletoux/SpoolerScanner">vletoux/SpoolerScanner</a></td>
        <td>Check if MS-RPRN is remotely available with powershell/c#</td>
    </tr>
    <tr>
        <td><a href="https://github.com/yogeshojha/rengine">yogeshojha/rengine</a></td>
        <td>reNgine is a reconnaissance engine(framework) that does end-to-end reconnaissance with the help of highly configurable scan engines and does information gathering about the target web application. reNgine makes use of various open-source tools and makes a configurable pipeline of reconnaissance.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ZeroPointSecurity/Domain-Enumeration-Tool">ZeroPointSecurity/Domain-Enumeration-Tool</a></td>
        <td>Perform Windows domain enumeration via LDAP</td>
    </tr>
</table>

## Initial Access

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/BeetleChunks/SpoolSploit">BeetleChunks/SpoolSploit</a></td>
        <td>A collection of Windows print spooler exploits containerized with other utilities for practical exploitation.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/shelld3v/PwnVPN">shelld3v/PwnVPN</a></td>
        <td>The best exploitation tool for SSL VPN 0day vulnerabilities</td>
    </tr>
</table>

## Execution

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/0xDivyanshu/Injector">0xDivyanshu/Injector</a></td>
        <td>Complete Arsenal of Memory injection and other techniques for red-teaming in Windows</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Aetsu/OffensivePipeline">Aetsu/OffensivePipeline</a></td>
        <td>OffensivePipeline allows to download, compile (without Visual Studio) and obfuscate C# tools for Red Team exercises.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/aeverj/NimShellCodeLoader">aeverj/NimShellCodeLoader</a></td>
        <td>Nim编写Windows平台shellcode免杀加载器</td>
    </tr>
    <tr>
        <td><a href="https://github.com/antonioCoco/SharPyShell">antonioCoco/SharPyShell</a></td>
        <td>SharPyShell - tiny and obfuscated ASP.NET webshell for C# web applications</td>
    </tr>
    <tr>
        <td><a href="https://github.com/api0cradle/LOLBAS">api0cradle/LOLBAS</a></td>
        <td>Living Off The Land Binaries and Scripts (and now also Libraries)</td>
    </tr>
    <tr>
        <td><a href="https://github.com/b1tg/rust-windows-shellcode">b1tg/rust-windows-shellcode</a></td>
        <td>Windows shellcode development in Rust</td>
    </tr>
    <tr>
        <td><a href="https://github.com/bats3c/DarkLoadLibrary">bats3c/DarkLoadLibrary</a></td>
        <td>LoadLibrary for offensive operations</td>
    </tr>
    <tr>
        <td><a href="https://github.com/bohops/GhostBuild">bohops/GhostBuild</a></td>
        <td>GhostBuild is a collection of simple MSBuild launchers for various GhostPack/.NET projects</td>
    </tr>
    <tr>
        <td><a href="https://github.com/boku7/bof-spawnSuspendedProcess">boku7/bof-spawnSuspendedProcess</a></td>
        <td>Cobalt Strike Beacon Object File (BOF) that takes the name of of a PE file as an argument and spawns the process in a suspended state</td>
    </tr>
    <tr>
        <td><a href="https://github.com/boku7/CobaltStrikeReflectiveLoader">boku7/CobaltStrikeReflectiveLoader</a></td>
        <td>Cobalt Strike User-Defined Reflective Loader written in Assembly & C for advanced evasion capabilities.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/boku7/winx64-InjectAllProcessesMeterpreter-Shellcode">boku7/winx64-InjectAllProcessesMeterpreter-Shellcode</a></td>
        <td>64bit Windows 10 shellcode that injects all processes with Meterpreter reverse shells.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/bytecode77/self-morphing-csharp-binary">bytecode77/self-morphing-csharp-binary</a></td>
        <td>Executable that mutates its own code</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cdong1012/Crab-Runner">cdong1012/Crab-Runner</a></td>
        <td>Shellcode runner in Rust</td>
    </tr>
    <tr>
        <td><a href="https://ChadSki/SharpNeedle">ChadSki/SharpNeedle</a></td>
        <td>Inject C# code into a running process</td>
    </tr>
    <tr>
        <td><a href="https://github.com/checkymander/Sharp-SMBExec">checkymander/Sharp-SMBExec</a></td>
        <td>SMBExec C# module</td>
    </tr>
    <tr>
        <td><a href="https://github.com/checkymander/Zolom">checkymander/Zolom</a></td>
        <td>C# Executable with embedded Python that can be used reflectively to run python code on systems without
            Python installed</td>
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
        <td><a href="https://github.com/Cn33liz/StarFighters">Cn33liz/StarFighters</a></td>
        <td>A JavaScript and VBScript Based Empire Launcher, which runs within their own embedded PowerShell Host.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cribdragg3r/Alaris">cribdragg3r/Alaris</a></td>
        <td>A protective and Low Level Shellcode Loader the defeats modern EDR systems.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cube0x0/SharpeningCobaltStrike">cube0x0/SharpeningCobaltStrike</a></td>
        <td>I realtime v35/40 dotnet compiler for your linux Cobalt Strike C2. New fresh compiled and obfuscated binary for each use</td>
    </tr>
    <tr>
        <td><a href="https://github.com/D00MFist/Go4aRun">D00MFist/Go4aRun</a></td>
        <td>Shellcode runner in GO that incorporates shellcode encryption, remote process injection, block dlls, and spoofed parent process</td>
    </tr> 
    <tr>
        <td><a href="https://github.com/DamonMohammadbagher/NativePayload_Tinjection">DamonMohammadbagher/NativePayload_Tinjection</a></td>
        <td>Remote Thread Injection by C#</td>
    </tr>
    <tr>
        <td><a href="https://github.com/darkr4y/geacon">darkr4y/geacon</a></td>
        <td>Practice Go programming and implement CobaltStrike's Beacon in Go</td>
    </tr>
    <tr>
        <td><a href="https://github.com/dtrizna/easy-hollow">dtrizna/easy-hollow</a></td>
        <td>Automated build for process hollowing shellcode loader. Build on top of TikiTorch and donut projects.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/EddieIvan01/memexec">EddieIvan01/memexec</a></td>
        <td>A library for loading and executing PE (Portable Executable) from memory without ever touching the disk</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Flangvik/SharpCollection">Flangvik/SharpCollection</a></td>
        <td>Nightly builds of common C# offensive tools, fresh from their respective master branches built and released
            in a CDI fashion using Azure DevOps release pipelines.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/FortyNorthSecurity/CIMplant">FortyNorthSecurity/CIMplant</a></td>
        <td>C# port of WMImplant which uses either CIM or WMI to query remote systems</td>
    </tr>
    <tr>
        <td><a href="https://github.com/FortyNorthSecurity/EDD">FortyNorthSecurity/EDD</a></td>
        <td>Enumerate Domain Data is designed to be similar to PowerView but in .NET. PowerView is essentially the ultimate domain enumeration tool, and we wanted a .NET implementation that we worked on ourselves. This tool was largely put together by viewing implementations of different functionality across a wide range of existing projects and combining them into EDD.</td>
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
        <td><a href="https://github.com/gigajew/WinXRunPE">gigajew/WinXRunPE</a></td>
        <td>Two C# RunPE's capable of x86 and x64 injections</td>
    </tr>
    <tr>
        <td><a href="https://github.com/hausec/MaliciousClickOnceMSBuild">hausec/MaliciousClickOnceMSBuild</a></td>
        <td>Basic C# Project that will take an MSBuild payload and run it with MSBuild via ClickOnce.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/JamesCooteUK/SharpSphere">JamesCooteUK/SharpSphere</a></td>
        <td>.NET Project for Attacking vCenter</td>
    </tr>
    <tr>
        <td><a href="https://github.com/jhalon/SharpCall">jhalon/SharpCall</a></td>
        <td>Simple PoC demonstrating syscall execution in C#</td>
    </tr>
    <tr>
        <td><a href="https://github.com/jfmaes/Invoke-DLLClone">jfmaes/Invoke-DLLClone</a></td>
        <td>Koppeling x Metatwin x LazySign</td>
    </tr>
    <tr>
        <td><a href="https://github.com/jfmaes/SharpZipRunner">jfmaes/SharpZipRunner</a></td>
        <td>Executes position independent shellcode from an encrypted zip</td>
    </tr>
    <tr>
        <td><a href="https://github.com/knight0x07/ImpulsiveDLLHijack">knight0x07/ImpulsiveDLLHijack</a></td>
        <td>C# based tool which automates the process of discovering and exploiting DLL Hijacks in target binaries. The Hijacked paths discovered can later be weaponized during Red Team Operations to evade EDR's.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/knownsec/shellcodeloader">knownsec/shellcodeloader</a></td>
        <td>ShellcodeLoader of windows can bypass AV.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mai1zhi2/SharpBeacon">mai1zhi2/SharpBeacon</a></td>
        <td>CobaltStrike Beacon written in .Net 4 用.net重写了stager及Beacon，其中包括正常上线、文件管理、进程管理、令牌管理、结合SysCall进行注入、原生端口转发、关ETW等一系列功能</td>
    </tr>
    <tr>
        <td><a href="https://github.com/maxlandon/wiregost">maxlandon/wiregost</a></td>
        <td>Golang Implant & Post-Exploitation Framework</td>
    </tr>
    <tr>
        <td><a href="https://github.com/memN0ps/RustSCRunner">memN0ps/RustSCRunner</a></td>
        <td>Shellcode Runner/Injector in Rust using NTDLL functions directly with the ntapi Library.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mgeeky/Stracciatella">mgeeky/Stracciatella</a></td>
        <td>OpSec-safe Powershell runspace from within C# (aka SharpPick) with AMSI, Constrained Language Mode and
            Script Block Logging disabled at startup</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Mr-Un1k0d3r/RedTeamCSharpScripts">Mr-Un1k0d3r/RedTeamCSharpScripts</a></td>
        <td>C# Script used for Red Team. These binaries can be used by Cobalt Strike execute-assembly or as standalone
            executable.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/nccgroup/GTFOBLookup">nccgroup/GTFOBLookup</a></td>
        <td>Offline command line lookup utility for GTFOBins</td>
    </tr>
    <tr>
        <td><a href="https://github.com/nettitude/RunPE">nettitude/RunPE</a></td>
        <td>C# Reflective loader for unmanaged binaries.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/NtRaiseHardError/NINA">NtRaiseHardError/NINA</a></td>
        <td>NINA: No Injection, No Allocation x64 Process Injection Technique</td>
    </tr>
    <tr>
        <td><a href="https://github.com/NVISOsecurity/blogposts/tree/master/MaraudersMap">NVISOsecurity Marauders Map</a></td>
        <td>The Marauders Map is meant to be used on assessments where you have gained GUI access to an enviornment. The Marauders Map is a DLL written in C#, enriched by the DllExport project to export functions that can serve as an entrypoint of invocation for unmanaged code such as rundll32.</td>
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
        <td><a href="https://github.com/rek7/fireELF">rek7/fireELF</a></td>
        <td>fireELF - Fileless Linux Malware Framework</td>
    </tr>
    <tr>
        <td><a href="https://gist.github.com/ropnop/fdd4e4ab537821eee5a1a751c044924f">ropnop/go-sharp-loader.go</a></td>
        <td>Example Go program with multiple .NET Binaries embedded</td>
    </tr>
    <tr>
        <td><a href="https://github.com/rvrsh3ll/NoMSBuild">rvrsh3ll/NoMSBuild</a></td>
        <td>MSBuild without MSbuild.exe</td>
    </tr>
    <tr>
        <td><a href="https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader">S3cur3Th1sSh1t/Invoke-SharpLoader</a></td>
        <td>Load encrypted and compressed C# Code from a remote Webserver or from a local file straight to memory and execute it there.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/S3cur3Th1sSh1t/Nim_CBT_Shellcode">S3cur3Th1sSh1t/Nim_CBT_Shellcode</a></td>
        <td>CallBack-Techniques for Shellcode execution ported to Nim</td>
    </tr>
    <tr>
        <td><a href="https://github.com/scythe-io/memory-module-loader">scythe-io/memory-module-loader</a></td>
        <td>An implementation of a Windows loader that can load dynamic-linked libraries (DLLs) directly from memory</td>
    </tr>
    <tr>
        <td><a href="https://github.com/secdev-01/AllTheThingsExec">secdev-01/AllTheThingsExec</a></td>
        <td>Executes Blended Managed/Unmanged Exports</td>
    </tr>
    <tr>
        <td><a href="https://github.com/SecIdiot/TitanLdr">SecIdiot/TitanLdr</a></td>
        <td>Titan: A crappy Reflective Loader written in C and assembly for Cobalt Strike. Redirects DNS Beacon over DoH</td>
    </tr>
    <tr>
        <td><a href="https://github.com/sh4hin/GoPurple">sh4hin/GoPurple</a></td>
        <td>Yet another shellcode runner consists of different techniques for evaluating detection capabilities of
            endpoint security solutions</td>
    </tr>
    <tr>
        <td><a href="https://github.com/snovvcrash/NimHollow">snovvcrash/NimHollow</a></td>
        <td>Nim implementation of Process Hollowing using syscalls (for educational purposes)</td>
    </tr>
    <tr>
        <td><a href="https://github.com/snovvcrash/peas">snovvcrash/peas</a></td>
        <td>Modified version of PEAS client for offensive operations</td>
    </tr>
    <tr>
        <td><a href="https://github.com/timwhitez/Doge-Loader">timwhitez/Doge-Loader</a></td>
        <td>🐶Cobalt Strike Shellcode Loader by Golang</td>
    </tr>
    <tr>
        <td><a href="https://github.com/TheCruZ/kdmapper">TheCruZ/kdmapper</a></td>
        <td>KDMapper is a simple tool that exploits iqvw64e.sys Intel driver to manually map non-signed drivers in memory</td>
    </tr>
    <tr>
        <td><a href="https://github.com/xforcered/InlineExecute-Assembly">xforcered/InlineExecute-Assembly</a></td>
        <td>InlineExecute-Assembly is a proof of concept Beacon Object File (BOF) that allows security professionals to perform in process .NET assembly execution as an alternative to Cobalt Strikes traditional fork and run execute-assembly module</td>
    </tr>
    <tr>
       <td><a href="https://github.com/xinbailu/DripLoader">xinbailu/DripLoader</a></td>
       <td>Evasive shellcode loader for bypassing event-based injection detection (PoC)</td>
   </tr>
    <tr>
        <td><a href="https://github.com/xinbailu/DripLoader-Ops">xinbailu/DripLoader-Ops</a></td>
        <td>a usable, cleaned-up version for script kiddies</td>
    </tr>
    <tr>
        <td><a href="https://github.com/xpn/NautilusProject">xpn/NautilusProject</a></td>
        <td>A collection of weird ways to execute unmanaged code in .NET</td>
    </tr>
    <tr>
        <td><a href="https://github.com/yqcs/ZheTian">yqcs/ZheTian</a></td>
        <td>ZheTian Powerful remote load and execute ShellCode tool</td>
    </tr>
    <tr>
        <td><a href="https://github.com/zerosum0x0/rcmd">zerosum0x0/rcmd</a></td>
        <td>Runs a command in another process</td>
    </tr>
</table>

### Manipulating Binary's Internal

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/aaaddress1/wowGrail">aaaddress1/wowGrail</a></td>
        <td>PoC: Rebuild A New Path Back to the Heaven's Gate (HITB 2021)</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Accenture/CLRvoyance">Accenture/CLRvoyance</a></td>
        <td>Managed assembly shellcode generation</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ajpc500/NimlineWhispers">ajpc500/NimlineWhispers</a></td>
        <td>A very proof-of-concept port of InlineWhispers for using syscalls in Nim projects.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Akaion/Bleak">Akaion/Bleak</a></td>
        <td>A Windows native DLL injection library that supports several methods of injection.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/boku7/AsmHalosGate">boku7/AsmHalosGate</a></td>
        <td>x64 Assembly HalosGate direct System Caller to evade EDR UserLand hooks</td>
    </tr>
    <tr>
        <td><a href="https://github.com/boku7/halosgate-ps">boku7/halosgate-ps</a></td>
        <td>Cobalt Strike BOF that uses a custom ASM HalosGate & HellsGate syscaller to return a list of processes</td>
    </tr>
    <tr>
        <td><a href="https://github.com/boku7/HellsGatePPID">boku7/HellsGatePPID</a></td> 
        <td>Assembly HellGate implementation that directly calls Windows System Calls and displays the PPID of the explorer.exe process</td>
    </tr>
    <tr>
        <td><a href="https://github.com/boku7/HOLLOW">boku7/HOLLOW</a></td>
        <td>EarlyBird process hollowing technique (BOF) - Spawns a process in a suspended state, inject shellcode, hijack main thread with APC, and execute shellcode</td>
    </tr>
    <tr>
        <td><a href="https://github.com/boku7/Ninja_UUID_Dropper">boku7/Ninja_UUID_Dropper</a></td>
        <td>Module Stomping, No New Thread, HellsGate syscaller, UUID Dropper for x64 Windows 10!</td>
    </tr>
    <tr>
        <td><a href="https://github.com/boku7/spawn">boku7/spawn</a></td>
        <td>Cobalt Strike BOF that spawns a sacrificial process, injects it with shellcode, and executes payload. Built to evade EDR/UserLand hooks by spawning sacrificial process with Arbitrary Code Guard (ACG), BlockDll, and PPID spoofing.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Cybellum/DoubleAgent">Cybellum/DoubleAgent</a></td>
        <td>DoubleAgent is a new Zero-Day technique for injecting code and maintaining persistence on a machine (i.e.
            auto-run).</td>
    </tr>
    <tr>
        <td><a href="https://github.com/DarthTon/Xenos">DarthTon/Xenos</a></td>
        <td>Windows dll injector</td>
    </tr>
    <tr>
        <td><a href="https://github.com/FalconForceTeam/SysWhispers2BOF">FalconForceTeam/SysWhispers2BOF</a></td>
        <td>Script to use SysWhispers2 direct system calls from Cobalt Strike BOFs</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Flangvik/SharpDllProxy">Flangvik/SharpDllProxy</a></td>
        <td>Retrieves exported functions from a legitimate DLL and generates a proxy DLL source code/template for DLL
            proxy loading or sideloading</td>
    </tr>
    <tr>
        <td><a href="https://github.com/forrest-orr/phantom-dll-hollower-poc">forrest-orr/phantom-dll-hollower-poc</a>
        </td>
        <td>Phantom DLL hollowing PoC</td>
    </tr>
    <tr>
        <td><a href="https://github.com/GetRektBoy724/JALSI">GetRektBoy724/JALSI</a></td>
        <td>JALSI - Just Another Lame Shellcode Injector</td>
    </tr>
    <tr>
        <td><a href="https://github.com/GetRektBoy724/TripleS">GetRektBoy724/TripleS</a></td>
        <td>Syscall Stub Stealer - Freshly steal Syscall stub straight from the disk</td>
    </tr>
    <tr>
        <td><a href="https://github.com/GoodstudyChina/APC-injection-x86-x64">GoodstudyChina/APC-injection-x86-x64</a>
        </td>
        <td>injdrv is a proof-of-concept Windows Driver for injecting DLL into user-mode processes using APC.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/jonatan1024/clrinject">jonatan1024/clrinject</a></td>
        <td>Injects C# EXE or DLL Assembly into every CLR runtime and AppDomain of another process.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/jthuraisamy/SysWhispers">jthuraisamy/SysWhispers</a></td>
        <td>SysWhispers helps with evasion by generating header/ASM files implants can use to make direct system calls.
        </td>
    </tr>
    <tr>
        <td><a href="https://github.com/jthuraisamy/SysWhispers2">jthuraisamy/SysWhispers2</a></td>
        <td>AV/EDR evasion via direct system calls.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Kara-4search/HellgateLoader_CSharp">Kara-4search/HellgateLoader_CSharp</a></td>
        <td>Load shelcode via HELLGATE, rewrite hellgate for learning purpose.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Kara-4search/MappingInjection_CSharp">Kara-4search/MappingInjection_CSharp</a></td>
        <td>MappingInjection via csharp</td>
    </tr>
    <tr>
        <td><a href="https://github.com/kyleavery/ThirdEye">kyleavery/ThirdEye</a></td>
        <td>Weaponizing CLRvoyance for Post-Ex .NET Execution</td>
    </tr>
    <tr>
        <td><a href="https://github.com/magnusstubman/dll-exports">magnusstubman/dll-exports</a></td>
        <td>Collection of DLL function export forwards for DLL export function proxying</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mgeeky/ElusiveMice">mgeeky/ElusiveMice</a></td>
        <td>Cobalt Strike User-Defined Reflective Loader with AV/EDR Evasion in mind</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mobdk/Sigma">mobdk/Sigma</a></td>
        <td>Execute shellcode with ZwCreateSection, ZwMapViewOfSection, ZwOpenProcess, ZwMapViewOfSection and ZwCreateThreadEx</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mobdk/Upsilon">mobdk/Upsilon</a></td>
        <td>Upsilon execute shellcode with syscalls - no API like NtProtectVirtualMemory is used</td>
    </tr>
    <tr>
        <td><a href="https://github.com/monoxgas/sRDI">monoxgas/sRDI</a></td>
        <td>Shellcode implementation of Reflective DLL Injection. Convert DLLs to position independent shellcode</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Moriarty2016/NimRDI">Moriarty2016/NimRDI</a></td>
        <td>RDI implementation in Nim</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ORCA666/EVA3">ORCA666/EVA3</a></td>
        <td>using hellsgate in EVA to get the syscalls</td>
    </tr>
    <tr>
        <td><a href="https://github.com/passthehashbrowns/DInvokeProcessHollowing">passthehashbrowns/DInvokeProcessHollowing</a></td>
        <td>This repository is an implementation of process hollowing shellcode injection using DInvoke from SharpSploit. DInvoke allows operators to use unmanaged code while avoiding suspicious imports or API hooking.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/richkmeli/Richkware">richkmeli/Richkware</a></td>
        <td>Framework for building Windows malware, written in C++</td>
    </tr>
    <tr>
        <td><a href="https://github.com/sad0p/d0zer">sad0p/d0zer</a></td>
        <td>Elf binary infector written in Golang</td>
    </tr>
    <tr>
        <td><a href="https://github.com/SheLLVM/SheLLVM">SheLLVM/SheLLVM</a></td>
        <td>A collection of LLVM transform and analysis passes to write shellcode in regular C</td>
    </tr>
    <tr>
        <td><a href="https://github.com/stephenfewer/ReflectiveDLLInjection">stephenfewer/ReflectiveDLLInjection</a>
        </td>
        <td>Reflective DLL injection is a library injection technique in which the concept of reflective programming is
            employed to perform the loading of a library from memory into a host process</td>
    </tr>
    <tr>
        <td><a href="https://github.com/slyd0g/UrbanBishopLocal">slyd0g/UrbanBishopLocal</a></td>
        <td>A port of FuzzySecurity's UrbanBishop project for inline shellcode execution. The execution vector uses a
            delegate vs an APC on a suspended threat at ntdll!RtlExitUserThread in UrbanBishop</td>
    </tr>
    <tr>
        <td><a href="https://github.com/TheWover/GhostLoader">TheWover/GhostLoader</a></td>
        <td>GhostLoader - AppDomainManager - Injection - 攻壳机动队</td>
    </tr>
    <tr>
        <td><a href="https://github.com/timwhitez/Doge-sRDI">timwhitez/Doge-sRDI</a></td>
        <td>Shellcode implementation of Reflective DLL Injection by Golang. Convert DLLs to position independent shellcode</td>
    </tr>
    <tr>
        <td><a href="https://github.com/trickster0/OffensiveRust">trickster0/OffensiveRust</a></td>
        <td>Rust Weaponization for Red Team Engagements.</td>
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
        <td><a href="https://github.com/BC-SECURITY/Offensive-VBA-and-XLS-Entanglement">BC-SECURITY/Offensive-VBA-and-XLS-Entanglement</a></td>
        <td>Offensive VBA and XLS Entanglement</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Binject/backdoorfactory">Binject/backdoorfactory</a></td>
        <td>A from-scratch rewrite of The Backdoor Factory - a MitM tool for inserting shellcode into all types of
            binaries on the wire.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/BishopFox/sliver">BishopFox/sliver</a></td>
        <td>Sliver is a general purpose cross-platform implant framework that supports C2 over Mutual-TLS, HTTP(S), and
            DNS. Implants are dynamically compiled with unique X.509 certificates signed by a per-instance certificate
            authority generated when you first run the binary.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/capt-meelo/Beaconator">capt-meelo/Beaconator</a></td>
        <td>A beacon generator using Cobalt Strike and PEzor.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cedowens/Mythic-Macro-Generator">cedowens/Mythic-Macro-Generator</a></td>
        <td>Python3 script to generate a macro to launch a Mythic payload. Author: Cedric Owens</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Ch0pin/AVIator">Ch0pin/AVIator</a></td>
        <td>AV|Ator is a backdoor generator utility, which uses cryptographic and injection techniques in order to bypass AV detection.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/connormcgarr/LittleCorporal">connormcgarr/LittleCorporal</a></td>
        <td>LittleCorporal: A C# Automated Maldoc Generator</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cseroad/bypassAV">cseroad/bypassAV</a></td>
        <td>借助Win-PS2EXE项目编写cna脚本方便快速生成免杀可执行文件</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cytopia/kusanagi">cytopia/kusanagi</a></td>
        <td>Kusanagi is a bind and reverse shell payload generator with obfuscation and badchar support.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/D00MFist/Mystikal">D00MFist/Mystikal</a></td>
        <td>macOS Initial Access Payload Generator</td>
    </tr>
    <tr>
        <td><a href="https://github.com/damienvanrobaeys/PS1-To-EXE-Generator">damienvanrobaeys/PS1-To-EXE-Generator</a>
        </td>
        <td>PS1 to EXE Generator: Create an EXE for your PS1 scripts</td>
    </tr>
    <tr>
        <td><a href="https://github.com/erikgeiser/govenom">erikgeiser/govenom</a></td>
        <td>govenom is a msfvenom-inspired cross-platform payload generator toolkit written in Go</td>
    </tr>
    <tr>
        <td><a href="https://github.com/forrest-orr/artifacts-kit">forrest-orr/artifacts-kit</a></td>
        <td>Pseudo-malicious usermode memory artifact generator kit designed to easily mimic the footprints left by real malware on an infected Windows OS.</td>
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
        <td><a href="https://github.com/frkngksl/Huan">frkngksl/Huan</a></td>
        <td>Encrypted PE Loader Generator</td>
    </tr>
    <tr>
        <td><a href="https://github.com/GetRektBoy724/MeterPwrShell">GetRektBoy724/MeterPwrShell</a></td>
        <td>Automated Tool That Generate The Perfect Powershell Payload</td>
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
        <td><a href="https://github.com/gloxec/CrossC2">gloxec/CrossC2</a></td>
        <td>Generate CobaltStrike's cross-platform payload</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Greenwolf/ntlm_theft">Greenwolf/ntlm_theft</a></td>
        <td>A tool for generating multiple types of NTLMv2 hash theft files by Jacob Wilkin (Greenwolf)</td>
    </tr>
    <tr>
        <td><a href="https://github.com/hasherezade/masm_shc">hasherezade/masm_shc</a></td>
        <td>A helper utility for creating shellcodes. Cleans MASM file generated by MSVC, gives refactoring hints.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/infosecn1nja/MaliciousMacroMSBuild">infosecn1nja/MaliciousMacroMSBuild</a></td>
        <td>Generates Malicious Macro and Execute Powershell or Shellcode via MSBuild Application Whitelisting Bypass.
        </td>
    </tr>
    <tr>
        <td><a href="https://github.com/jfmaes/SharpLNKGen-UI">jfmaes/SharpLNKGen-UI</a></td>
        <td>UI for creating LNKs</td>
    </tr>
    <tr>
        <td><a href="https://github.com/jonaslejon/malicious-pdf">jonaslejon/malicious-pdf</a></td>
        <td>Generate a bunch of malicious pdf files with phone-home functionality. Can be used with Burp Collaborator</td>
    </tr>
    <tr>
        <td><a href="https://github.com/l373/GIVINGSTORM">l373/GIVINGSTORM</a></td>
        <td>Infection vector that bypasses AV, IDS, and IPS. (For now...)</td>
    </tr>
    <tr>
        <td><a href="https://github.com/lockedbyte/CVE-2021-40444">lockedbyte/CVE-2021-40444</a></td>
        <td>Malicious docx generator to exploit CVE-2021-40444 (Microsoft Office Word Remote Code Execution)</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mdsecactivebreach/SharpShooter">mdsecactivebreach/SharpShooter</a></td>
        <td>SharpShooter is a payload creation framework for the retrieval and execution of arbitrary CSharp source
            code.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/med0x2e/GadgetToJScript">med0x2e/GadgetToJScript</a></td>
        <td>A tool for generating .NET serialized gadgets that can trigger .NET assembly load/execution when deserialized using BinaryFormatter from JS/VBS/VBA based scripts.</td>
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
        <td><a href="https://github.com/optiv/ScareCrow">optiv/ScareCrow</a></td>
        <td>ScareCrow - Payload creation framework designed around EDR bypass.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Plazmaz/LNKUp">Plazmaz/LNKUp</a></td>
        <td>Generates malicious LNK file payloads for data exfiltration</td>
    </tr>
    <tr>
        <td><a href="https://github.com/postrequest/xeca">postrequest/xeca</a></td>
        <td>PowerShell payload generator</td>
    </tr>
    <tr>
        <td><a href="https://github.com/praetorian-inc/Matryoshka">praetorian-inc/Matryoshka</a></td>
        <td>Matryoshka loader is a tool that red team operators can leverage to generate shellcode for Microsoft Office document phishing payloads.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/redcanaryco/chain-reactor">redcanaryco/chain-reactor</a></td>
        <td>Chain Reactor is an open source framework for composing executables that simulate adversary behaviors and
            techniques on Linux endpoints.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/redcode-labs/GoSH">redcode-labs/GoSH</a></td>
        <td>Golang reverse/bind shell generator</td>
    </tr>
    <tr>
        <td><a href="https://github.com/redcode-labs/SNOWCRASH">redcode-labs/SNOWCRASH</a></td>
        <td>A polyglot payload generator</td>
    </tr>
    <tr>
        <td><a href="https://www.revshells.com/">Reverse Shell Generator</a></td>
        <td>Reverse Shell Generator</td>
    </tr>
    <tr>
        <td><a href="https://github.com/s0lst1c3/dropengine">s0lst1c3/dropengine</a></td>
        <td>DropEngine provides a malleable framework for creating shellcode runners, allowing operators to choose from a selection of components and combine them to create highly sophisticated payloads within seconds.DropEngine provides a malleable framework for creating shellcode runners, allowing operators to choose from a selection of components and combine them to create highly sophisticated payloads within seconds.DropEngine provides a malleable framework for creating shellcode runners, allowing operators to choose from a selection of components and combine them to create highly sophisticated payloads within seconds.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/sevagas/macro_pack">sevagas/macro_pack</a></td>
        <td>macro_pack is a tool used to automatize obfuscation and generation of MS Office documents for pentest, demo,
            and social engineering assessments. The goal of macro_pack is to simplify antimalware bypass and automatize
            the process from vba generation to final Office document generation.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/STMSolutions/boobsnail">STMSolutions/boobsnail</a></td>
        <td>BoobSnail allows generating Excel 4.0 XLM macro. Its purpose is to support the RedTeam and BlueTeam in XLM macro generation.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/t3hbb/NSGenCS">t3hbb/NSGenCS</a></td>
        <td>Extendable payload obfuscation and delivery framework</td>
    </tr>
    <tr>
        <td><a href="https://github.com/TheWover/donut">TheWover/donut</a></td>
        <td>Generates x86, x64, or AMD64+x86 position-independent shellcode that loads .NET Assemblies, PE files, and
            other Windows payloads from memory and runs them with parameters</td>
    </tr>
    <tr>
        <td><a href="https://github.com/threatexpress/cobaltstrike_payload_generator">threatexpress/cobaltstrike_payload_generator</a></td>
        <td>Quickly generate every payload type for each listener and optionally host via HTTP.</td>
    </tr>
    <tr>
        <td><a href="https//github.com/trustedsec/unicorn">trustedsec/unicorn</a></td>
        <td>Unicorn is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory.
            Based on Matthew Graeber's powershell attacks and the powershell bypass technique presented by David Kennedy
            (TrustedSec) and Josh Kelly at Defcon 18.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Wra7h/Single-Dose">Wra7h/Single-Dose</a></td>
        <td>Generate process injection binaries</td>
    </tr>
    <tr>
        <td><a href="https://github.com/X-C3LL/xlsxPoison">X-C3LL/xlsxPoisoN</a></td>
        <td>Just a PoC to turn xlsx (regular Excel files) into xlsm (Excel file with macro) and slipping inside a macro (vbaProject.bin)</td>
    </tr>
</table>

## Persistence

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/0xthirteen/SharpStay">0xthirteen/SharpStay</a></td>
        <td>.NET project for installing Persistence</td>
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
        <td><a href="https://github.com/ben0xa/doucme">ben0xa/doucme</a></td>
        <td>This leverages the NetUserAdd Win32 API to create a new computer account. This is done by setting the usri1_priv of the USER_INFO_1 type to 0x1000. The primary goal is to avoid the normal detection of new user created events (4720).</td>
    </tr>
    <tr>
        <td><a href="https://github.com/CyborgSecurity/PoisonApple">CyborgSecurity/PoisonApple</a></td>
        <td>Command-line tool to perform various persistence mechanism techniques on macOS. This tool was designed to be used by threat hunters for cyber threat emulation purposes.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/djhohnstein/SharpSC">djhohnstein/SharpSC</a></td>
        <td>Simple .NET assembly to interact with services.</td>
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
        <td><a href="https://github.com/RedSection/printjacker">RedSection/printjacker</a></td>
        <td>Hijack Printconfig.dll to execute shellcode</td>
    </tr>
    <tr>
        <td><a href="https://github.com/S4R1N/ZoomPersistence">S4R1N/ZoomPersistence</a></td>
        <td>Zoom Persistence Aggressor and Handler</td>
    </tr>
    <tr>
        <td><a href="https://github.com/slaeryan/MIDNIGHTTRAIN">slaeryan/MIDNIGHTTRAIN</a></td>
        <td>Covert Stage-3 Persistence Framework</td>
    </tr>
    <tr>
        <td><a href="https://github.com/vivami/OutlookParasite">vivami/OutlookParasite</a></td>
        <td>Outlook persistence using VSTO add-ins</td>
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
        <td><a href="https://github.com/antonioCoco/RemotePotato0">antonioCoco/RemotePotato0</a></td>
        <td>Just another "Won't Fix" Windows Privilege Escalation from User to Domain Admin.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/antonioCoco/RogueWinRM">antonioCoco/RogueWinRM</a></td>
        <td>Windows Local Privilege Escalation from Service Account to System</td>
    </tr>
    <tr>
        <td><a href="https://github.com/antonioCoco/RunasCs">antonioCoco/RunasCs</a></td>
        <td>RunasCs - Csharp and open version of windows builtin runas.exe</td>
    </tr>
    <tr>
        <td><a href="https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite">carlospolop/privilege-escalation-awesome-scripts-suite</a>
        </td>
        <td>PEASS - Privilege Escalation Awesome Scripts SUITE (with colors)</td>
    </tr>
    <tr>
        <td><a href="https://github.com/CCob/SweetPotato">CCob/SweetPotato</a></td>
        <td>Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019</td>
    </tr>
    <tr>
        <td><a href="https://github.com/CMatri/Gotato">CMatri/Gotato</a></td>
        <td>Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/eladshamir/Whisker">eladshamir/Whisker</a></td>
        <td>Whisker is a C# tool for taking over Active Directory user and computer accounts by manipulating their msDS-KeyCredentialLink attribute, effectively adding "Shadow Credentials" to the target account.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/eloypgz/certi">eloypgz/certi</a></td>
        <td>Utility to play with ADCS, allows to request tickets and collect information about related objects. Basically, it's the impacket copy of Certify. Thanks to @harmj0y and @tifkin_ for its great work with ADCS.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/EspressoCake/Toggle_Token_Privileges_BOF">EspressoCake/Toggle_Token_Privileges_BOF</a></td>
        <td>Syscall BOF to arbitrarily add/detract process token privilege rights.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/GhostPack/ForgeCert">GhostPack/ForgeCert</a></td>
        <td>ForgeCert uses the BouncyCastle C# API and a stolen Certificate Authority (CA) certificate + private key to forge certificates for arbitrary users capable of authentication to Active Directory.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/GoSecure/WSuspicious">GoSecure/WSuspicious</a></td>
        <td>WSuspicious - A tool to abuse insecure WSUS connections for privilege escalationsWSuspicious - A tool to abuse insecure WSUS connections for privilege escalations</td>
    </tr>
    <tr>
        <td><a href="https://github.com/gtworek/Priv2Admin">gtworek/Priv2Admin</a></td>
        <td>Exploitation paths allowing you to (mis)use the Windows Privileges to elevate your rights within the OS.</td>
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
        <td><a href="https://github.com/jacob-baines/concealed_position">jacob-baines/concealed_position</a></td>
        <td>Bring your own print driver privilege escalation tool</td>
    </tr>
    <tr>
        <td><a href="https://github.com/liamg/traitor">liamg/traitor</a></td>
        <td>Automatic Linux privesc via exploitation of low-hanging fruit e.g. gtfobins</td>
    </tr>
    <tr>
        <td><a href="https://github.com/nccgroup/nccfsas/tree/main/Tools/spoolsystem">nccgroup/ncssfas - SpoolSystem</a></td>
        <td>SpoolSystem is a CNA script for Cobalt Strike which uses the Print Spooler named pipe impersonation trick to gain SYSTEM privileges.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ollypwn/Certipy">ollypwn/Certipy</a></td>
        <td>Python implementation for Active Directory certificate abuse</td>
    </tr>
    <tr>
        <td><a href="https://github.com/rxwx/spoolsystem">rxwx/spoolsystem</a></td>
        <td>Print Spooler Named Pipe Impersonation for Cobalt Strike</td>
    </tr>
    <tr>
        <td><a href="https://github.com/sailay1996/delete2SYSTEM">sailay1996/delete2SYSTEM</a></td>
        <td>Weaponizing for Arbitrary Files/Directories Delete bugs to Get NT AUTHORITY\SYSTEM</td>
    </tr>
    <tr>
        <td><a href="https://github.com/S3cur3Th1sSh1t/SharpImpersonation">S3cur3Th1sSh1t/SharpImpersonation</a></td>
        <td>A User Impersonation tool - via Token or Shellcode injection</td>
    </tr>
    <tr>
        <td><a href="https://github.com/slyd0g/PrimaryTokenTheft">slyd0g/PrimaryTokenTheft</a></td>
        <td>Steal a primary token and spawn cmd.exe using the stolen token</td>
    </tr>
    <tr>
        <td><a href="https://github.com/TsukiCTF/Lovely-Potato">TsukiCTF/Lovely-Potato</a></td>
        <td>Automating juicy potato local privilege escalation exploit for penetration testers.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/thehappydinoa/rootOS">thehappydinoa/rootOS</a></td>
        <td>macOS Privilege Escalation Helper</td>
    </tr>
</table>

## Defense Evasion

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/0xZDH/redirect.rules">0xZDH/redirect.rules</a></td>
        <td>Quick and dirty dynamic redirect.rules generator</td>
    </tr>
    <tr>
        <td><a href="https://github.com/3gstudent/Eventlogedit-evtx--Evolution">3gstudent/Eventlogedit-evtx--Evolution</a></td>
        <td>Remove individual lines from Windows XML Event Log (EVTX) files</td>
    </tr>
    <tr>
        <td><a href="https://github.com/89luca89/pakkero">89luca89/pakkero</a></td>
        <td>Pakkero is a binary packer written in Go made for fun and educational purpose. Its main goal is to take in
            input a program file (elf binary, script, even appimage) and compress it, protect it from tampering and
            intrusion.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/airzero24/WMIReg">airzero24/WMIReg</a></td>
        <td>PoC to interact with local/remote registry hives through WMI</td>
    </tr>
    <tr>
        <td><a href="https://github.com/AnErrupTion/LoGiC.NET">AnErrupTion/LoGiC.NET</a></td>
        <td>A more advanced free and open .NET obfuscator using dnlib.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/anthemtotheego/Detect-Hooks">anthemtotheego/Detect-Hooks</a></td>
        <td>Proof of concept Beacon Object File (BOF) that attempts to detect userland hooks in place by AV/EDR</td>
    </tr>
    <tr>
        <td><a href="https://github.com/api0cradle/UltimateAppLockerByPassList">api0cradle/UltimateAppLockerByPassList</a>
        </td>
        <td>The goal of this repository is to document the most common techniques to bypass AppLocker.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Arvanaghi/CheckPlease">Arvanaghi/CheckPlease</a></td>
        <td>Sandbox evasion modules written in PowerShell, Python, Go, Ruby, C, C#, Perl, and Rust.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/asaurusrex/DoppelGate">asaurusrex/DoppelGate</a></td>
        <td>This project is designed to provide a method of extracting syscalls dynamically directly from on-disk ntdll. Userland hooks have become prevalent in many security products these days, and bypassing these hooks is a great way for red teamers/pentesters to bypass these defenses.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/asaurusrex/EDR_Userland_Hook_Checker">asaurusrex/EDR_Userland_Hook_Checker</a></td>
        <td>Project to check which Nt/Zw functions your local EDR is hooking</td>
    </tr>
    <tr>
        <td><a href="https://github.com/audibleblink/dummyDLL">audibleblink/dummyDLL</a></td>
        <td>Utility for hunting UAC bypasses or COM/DLL hijacks that alerts on the exported function that was consumed.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/AzAgarampur/byeintegrity4-uac">AzAgarampur/byeintegrity4-uac</a></td>
        <td>Bypass UAC by abusing the Windows Defender Firewall Control Panel, environment variables, and shell protocol handlers</td>
    </tr>
    <tr>
        <td><a href="https://github.com/AzAgarampur/byeintegrity8-uac">AzAgarampur/byeintegrity8-uac</a></td>
        <td>Bypass UAC at any level by abusing the Program Compatibility Assistant with RPC, WDI, and more Windows components</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Bashfuscator/Bashfuscator">Bashfuscator/Bashfuscator</a></td>
        <td>A fully configurable and extendable Bash obfuscation framework. This tool is intended to help both red team and blue team.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/bats3c/Ghost-In-The-Logs">bats3c/Ghost-In-The-Logs</a></td>
        <td>Evade sysmon and windows event logginEvade sysmon and windows event loggingg</td>
    </tr>
    <tr>
        <td><a href="https://github.com/BaumFX/cpp-anti-debug">BaumFX/cpp-anti-debug</a></td>
        <td>anti debugging library in c++.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/BinaryScary/NET-Obfuscate">BinaryScary/NET-Obfuscate</a></td>
        <td>Obfuscate ECMA CIL (.NET IL) assemblies to evade Windows Defender AMSI</td>
    </tr>
    <tr>
        <td><a href="https://github.com/bhumic/PErmutator">bhumic/PErmutator</a></td>
        <td>The goal of this project is to create a permutation engine for PE files. The engine should randomize the executable parts of the file.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/bohops/UltimateWDACBypassList">bohops/UltimateWDACBypassList</a></td>
        <td>A centralized resource for previously documented WDAC bypass techniques</td>
    </tr>
    <tr>
        <td><a href="https://github.com/boku7/injectAmsiBypass">boku7/injectAmsiBypass</a></td>
        <td>Cobalt Strike BOF - Bypass AMSI in a remote process with code injection.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/boku7/injectEtwBypass?s=09">boku7/injectEtwBypass</a></td>
        <td>CobaltStrike BOF - Inject ETW Bypass into Remote Process via Syscalls (HellsGate|HalosGate)</td>
    </tr>
    <tr>
        <td><a href="https://github.com/br-sn/CheekyBlinder">br-sn/CheekyBlinder</a></td>
        <td>Enumerating and removing kernel callbacks using signed vulnerable drivers</td>
    </tr>
    <tr>
        <td><a href="https://github.com/burrowers/garble">burrowers/garble</a></td>
        <td>Obfuscate Go builds</td>
    </tr>
    <tr>
        <td><a href="https://github.com/c0de90e7/GhostWriting">c0de90e7/GhostWriting</a></td>
        <td>GhostWriting Injection Technique.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/calebstewart/bypass-clm">calebstewart/bypass-clm</a></td>
        <td>PowerShell Constrained Language Mode Bypass</td>
    </tr>
    <tr>
        <td><a href="https://github.com/CCob/SharpBlock">CCob/SharpBlock</a></td>
        <td>A method of bypassing EDR's active projection DLL's by preventing entry point execution.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cobbr/PSAmsi">cobbr/PSAmsi</a></td>
        <td>PSAmsi is a tool for auditing and defeating AMSI signatures.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cipheras/obfus">cipheras/obfus</a></td>
        <td>Curated list of examples, tools, frameworks, etc in various languages with various techniques for obfuscation of RATs, malwares, etc. Only for learning purposes & red teaming.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cnsimo/BypassUAC">cnsimo/BypassUAC</a></td>
        <td>Use ICMLuaUtil to Bypass UAC!</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cwolff411/powerob">cwolff411/powerob</a></td>
        <td>An on-the-fly Powershell script obfuscator meant for red team engagements. Built out of necessity.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cyberark/Evasor">cyberark/Evasor</a></td>
        <td>A tool to be used in post exploitation phase for blue and red teams to bypass APPLICATIONCONTROL policies</td>
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
        <td><a href="https://github.com/danielbohannon/Invoke-CradleCrafter">danielbohannon/Invoke-CradleCrafter</a>
        </td>
        <td>PowerShell Remote Download Cradle Generator & Obfuscator</td>
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
        <td><a href="https://github.com/dndx/phantun">dndx/phantun</a></td>
        <td>Transforms UDP stream into (fake) TCP streams that can go through Layer 3 & Layer 4 (NAPT) firewalls/NATs.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/dsnezhkov/zombieant">dsnezhkov/zombieant</a></td>
        <td>Zombie Ant Farm: Primitives and Offensive Tooling for Linux EDR evasion.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/EgeBalci/Amber">EgeBalci/Amber</a></td>
        <td>amber is a reflective PE packer for bypassing security products and mitigations. It can pack regularly
            compiled PE files into reflective payloads that can load and execute itself like a shellcode.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/EgeBalci/sgn">EgeBalci/sgn</a></td>
        <td>Shikata ga nai (仕方がない) encoder ported into go with several improvements</td>
    </tr>
    <tr>
        <td><a href="https://github.com/EspressoCake/Firewall_Walker_BOF">EspressoCake/Firewall_Walker_BOF</a></td>
        <td>A BOF to interact with COM objects associated with the Windows software firewall.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/EspressoCake/Self_Deletion_BOF">EspressoCake/Self_Deletion_BOF</a></td>
        <td>BOF implementation of the research by @jonaslyk and the drafted PoC from @LloydLabs</td>
    </tr>
    <tr>
        <td><a href="https://github.com/FatRodzianko/SharpBypassUAC">FatRodzianko/SharpBypassUAC</a></td>
        <td>C# tool for UAC bypasses</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ffuf/pencode">ffuf/pencode</a></td>
        <td>Complex payload encoder</td>
    </tr>
    <tr>
        <td><a href="https://github.com/fireeye/OfficePurge">fireeye/OfficePurge</a></td>
        <td>VBA purge your Office documents with OfficePurge. VBA purging removes P-code from module streams within Office documents.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Flangvik/AMSI.fail">Flangvik/AMSI.fail</a></td>
        <td>C# Azure Function with an HTTP trigger that generates obfuscated PowerShell snippets that break or disable AMSI for the current process.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Flangvik/NetLoader">Flangvik/NetLoader</a></td>
        <td>Loads any C# binary in mem, patching AMSI + ETW.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/GetRektBoy724/TripleS">GetRektBoy724/TripleS</a></td>
        <td>Syscall Stub Stealer - Freshly steal Syscall stub straight from the disk</td>
    </tr>
    <tr>
        <td><a href="https://github.com/HackOvert/AntiDBG">HackOvert/AntiDBG</a></td>
        <td>A bunch of Windows anti-debugging tricks for x86 and x64.</td>
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
        <td><a href="https://github.com/iomoath/PowerShx">iomoath/PowerShx</a></td>
        <td>Run Powershell without software restrictions.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/jason-klein/signed-nsis-exe-append-payload">jason-klein/signed-nsis-exe-append-payload</a></td>
        <td>Append a custom data payload to a digitally signed NSIS .exe installer</td>
    </tr>
    <tr>
        <td><a href="https://github.com/jfmaes/LazySign">jfmaes/LazySign</a></td>
        <td>Create fake certs for binaries using windows binaries and the power of bat files</td>
    </tr>
    <tr>
        <td><a href="https://github.com/jfmaes/sharpbysentinel">jfmaes/sharpbysentinel</a></td>
        <td>Kill telemetry to sentinel</td>
    </tr>
    <tr>
        <td><a href="https://github.com/jfmaes/SharpNukeEventLog">jfmaes/SharpNukeEventLog</a></td>
        <td>nuke that event log using some epic dinvoke fu</td>
    </tr>
    <tr>
        <td><a href="https://github.com/JoelGMSec/Invoke-Stealth">JoelGMSec/Invoke-Stealth</a></td>
        <td>Simple & Powerful PowerShell Script Obfuscator</td>
    </tr>
    <tr>
        <td><a href="https://github.com/jthuraisamy/TelemetrySourcerer">jthuraisamy/TelemetrySourcerer</a></td>
        <td>Enumerate and disable common sources of telemetry used by AV/EDR.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Kara-4search/FullDLLUnhooking_CSharp">Kara-4search/FullDLLUnhooking_CSharp</a></td>
        <td>Unhook DLL via cleaning the DLL 's .text section</td>
    </tr>
    <tr>
        <td><a href="https://github.com/karttoon/trigen">karttoon/trigen</a></td>
        <td>Trigen is a Python script which uses different combinations of Win32 function calls in generated VBA to execute shellcode.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/kernelm0de/ProcessHider">kernelm0de/ProcessHider</a></td>
        <td>Hide Process From Task Manager using Usermode API Hooking</td>
    </tr>
    <tr>
        <td><a href="https://github.com/klezVirus/chameleon">klezVirus/chameleon</a></td>
        <td>Chameleon is yet another PowerShell obfuscation tool designed to bypass AMSI and commercial antivirus solutions.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/klezVirus/inceptor">klezVirus/inceptor</a></td>
        <td>Template-Driven AV/EDR Evasion Framework</td>
    </tr>
    <tr>
        <td><a href="https://github.com/last-byte/unDefender">last-byte/unDefender</a></td>
        <td>Killing your preferred antimalware by abusing native symbolic links and NT paths.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/lawiet47/STFUEDR">lawiet47/STFUEDR</a></td>
        <td>Silence EDRs by removing kernel callbacks</td>
    </tr>
    <tr>
        <td><a href="https://github.com/matterpreter/DefenderCheck">matterpreter/DefenderCheck</a></td>
        <td>Identifies the bytes that Microsoft Defender flags on.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/matterpreter/SHAPESHIFTER">matterpreter/SHAPESHIFTERmatterpreter/SHAPESHIFTER</a></td>
        <td>Companion PoC for the "Adventures in Dynamic Evasion" blog post</td>
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
        <td><a href="https://github.com/med0x2e/NoAmci">med0x2e/NoAmci</a></td>
        <td>Using DInvoke to patch AMSI.dll in order to bypass AMSI detections triggered when loading .NET tradecraft via Assembly.Load().</td>
    </tr>
    <tr>
        <td><a href="https://github.com/med0x2e/SigFlip">med0x2e/SigFlip</a></td>
        <td>SigFlip is a tool for patching authenticode signed PE files (exe, dll, sys ..etc) without invalidating or breaking the existing signature.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mgeeky/ShellcodeFluctuation">mgeeky/ShellcodeFluctuation</a></td>
        <td>An in-memory evasion technique fluctuating shellcode memory protection between RW & RX and encrypting/decrypting contents</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mgeeky/Stracciatella">mgeeky/Stracciatella</a></td>
        <td>OpSec-safe Powershell runspace from within C# (aka SharpPick) with AMSI, Constrained Language Mode and Script Block Logging disabled at startup</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mgeeky/ThreadStackSpoofer">mgeeky/ThreadStackSpoofer</a></td>
        <td>Thread Stack Spoofing - PoC for an advanced In-Memory evasion technique allowing to better hide injected shellcode's memory allocation from scanners and analysts.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/MinervaLabsResearch/CoffeeShot">MinervaLabsResearch/CoffeeShot</a></td>
        <td>CoffeeShot: Avoid Detection with Memory Injection</td>
    </tr>
    <tr>
        <td><a href="https://github.com/m0rv4i/Ridgway">m0rv4i/Ridgway</a></td>
        <td>A quick tool for hiding a new process running shellcode.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/nccgroup/demiguise">nccgroup/demiguise</a></td>
        <td>HTA encryption tool for RedTeams</td>
    </tr>
    <tr>
        <td><a href="https://github.com/netbiosX/AMSI-Provider">netbiosX/AMSI-Provider</a></td>
        <td>A fake AMSI Provider which can be used for persistence.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/netero1010/TrustedPath-UACBypass-BOF">netero1010/TrustedPath-UACBypass-BOF</a></td>
        <td>Cobalt Strike beacon object file implementation for trusted path UAC bypass. The target executable will be called without involving "cmd.exe" by using DCOM object.</td>
    </tr>
    <tr>
        <td><a href="https://gitlab.com/nephosec/bof-adios">nephosec/bof-adios</a></td>
        <td>Implementation of Self Deleting Executables</td>
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
        <td><a href="https://github.com/outflanknl/TamperETW">outflanknl/TamperETW</a></td>
        <td>PoC to demonstrate how CLR ETW events can be tampered.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/pathtofile/SealighterTI">pathtofile/SealighterTI</a></td>
        <td>Combining Sealighter with unpatched exploits to run the Threat-Intelligence ETW Provider</td>
    </tr>
    <tr>
        <td><a href="https://github.com/peewpw/Invoke-PSImage">peewpw/Invoke-PSImage</a></td>
        <td>Embeds a PowerShell script in the pixels of a PNG file and generates a oneliner to execute</td>
    </tr>
    <tr>
        <td><a href="https://github.com/PELock/JObfuscator-Python">PELock/JObfuscator-Python</a></td>
        <td>JObfuscator is a source code obfuscator for the Java language. Protect Java source code & algorithms from hacking, cracking, reverse engineering, decompilation & technology theft.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Pepitoh/VBad">Pepitoh/VBad</a></td>
        <td>VBA Obfuscation Tools combined with an MS office document generator</td>
    </tr>
    <tr>
        <td><a href="https://github.com/phra/PEzor">phra/PEzor</a></td>
        <td>Open-Source PE Packer</td>
    </tr>
    <tr>
        <td><a href="https://github.com/PwnDexter/SharpEDRChecker">PwnDexter/SharpEDRChecker</a></td>
        <td>Checks running processes, process metadata, Dlls loaded into your current process and the each DLLs metadata, common install directories, installed services and each service binaries metadata, installed drivers and each drivers metadata, all for the presence of known defensive products such as AV's, EDR's and logging tools.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/rasta-mouse/AmsiScanBufferBypass">rasta-mouse/AmsiScanBufferBypass</a></td>
        <td>Bypass AMSI by patching AmsiScanBuffer</td>
    </tr>
    <tr>
        <td><a href="https://github.com/RedCursorSecurityConsulting/PPLKiller">RedCursorSecurityConsulting/PPLKiller</a></td>
        <td>Tool to bypass LSA Protection (aka Protected Process Light)</td>
    </tr>
    <tr>
        <td><a href="https://github.com/rmdavy/HeapsOfFun">rmdavy/HeapsOfFun</a></td>
        <td>AMSI Bypass Via the Heap</td>
    </tr>
    <tr>
        <td><a href="https://github.com/RythmStick/AMSITrigger">RythmStick/AMSITrigger</a></td>
        <td>Hunting for Malicious Strings</td>
    </tr>
    <tr>
        <td><a href="https://github.com/S1ckB0y1337/TokenPlayer">S1ckB0y1337/TokenPlayer</a></td>
        <td>Manipulating and Abusing Windows Access Tokens.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/secretsquirrel/SigThief">secretsquirrel/SigThief</a></td>
        <td>Stealing Signatures and Making One Invalid Signature at a Time</td>
    </tr>
        <td><a href="https://github.com/sinfulz/JustEvadeBro">sinfulz/JustEvadeBro</a></td>
        <td>JustEvadeBro, a cheat sheet which will aid you through AMSI/AV evasion & bypasses.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/slyd0g/SharpCrashEventLog">slyd0g/SharpCrashEventLog</a></td>
        <td>C# port of LogServiceCrash</td>
    </tr>
    <tr>
        <td><a href="https://github.com/SolomonSklash/SleepyCrypt">SolomonSklash/SleepyCrypt</a></td>
        <td>A shellcode function to encrypt a running process image when sleeping.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/the-xentropy/xencrypt">the-xentropy/xencrypt</a></td>
        <td>A PowerShell script anti-virus evasion tool</td>
    </tr>
    <tr>
        <td><a href="https://github.com/TheWover/CertStealer">TheWover/CertStealer</a></td>
        <td>A .NET tool for exporting and importing certificates without touching disk.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ThomasThelen/Anti-Debugging">ThomasThelen/Anti-Debugging</a></td>
        <td>A collection of c++ programs that demonstrate common ways to detect the presence of an attached debugger.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/tomcarver16/AmsiHook">tomcarver16/AmsiHook</a></td>
        <td>AmsiHook is a project I created to figure out a bypass to AMSI via function hooking.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/tokyoneon/chimera">tokyoneon/chimera</a></td>
        <td>Chimera is a (shiny and very hack-ish) PowerShell obfuscation script designed to bypass AMSI and commercial
            antivirus solutions.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Tylous/Limelighter">Tylous/Limelighter</a></td>
        <td>A tool for generating fake code signing certificates or signing real ones</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Unknow101/FuckThatPacker">Unknow101/FuckThatPacker</a></td>
        <td>A simple python packer to easily bypass Windows Defender</td>
    </tr>
    <tr>
        <td><a href="https://github.com/xct/morbol">xct/morbol</a></td>
        <td>Simple AV Evasion for PE Files</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Yaxser/Backstab">Yaxser/Backstab</a></td>
        <td>A tool to kill antimalware protected processes</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Yet-Zio/WusaBypassUAC">Yet-Zio/WusaBypassUAC</a></td>
        <td>UAC bypass abusing WinSxS in "wusa.exe".</td>
    </tr>
    <tr>
        <td><a href="https://github.com/zeroperil/HookDump">zeroperil/HookDump</a></td>
        <td>Security product hook detection</td>
    </tr>
    <tr>
        <td><a href="https://github.com/zeroSteiner/crimson-forge">zeroSteiner/crimson-forge</a></td>
        <td>Crimson Forge intends to provide sustainable evasion capabilities for native code on the x86 and AMD64 architectures.</td>
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
        <td><a href="https://github.com/alfarom256/BOF-ForeignLsass">alfarom256/BOF-ForeignLsass</a></td>
        <td>LSASS Dumping With Foreign Handles</td>
    </tr>
    <tr>
        <td><a href="https://github.com/anthemtotheego/CredBandit">anthemtotheego/CredBandit</a></td>
        <td>Proof of concept Beacon Object File (BOF) that uses static x64 syscalls to perform a complete in memory dump of a process and send that back through your already existing Beacon communication channel</td>
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
        <td><a href="https://github.com/Barbarisch/forkatz">Barbarisch/forkatz</a></td>
        <td>credential dump using foreshaw technique using SeTrustedCredmanAccessPrivilege</td>
    </tr>
    <tr>
        <td><a href="https://github.com/blacklanternsecurity/TREVORspray">blacklanternsecurity/TREVORspray</a></td>
        <td>A featureful round-robin SOCKS proxy and Python O365 sprayer based on MSOLSpray which uses the Microsoft Graph API</td>
    </tr>
    <tr>
        <td><a href="https://github.com/byt3bl33d3r/SprayingToolkit">byt3bl33d3r/SprayingToolkit</a></td>
        <td>Scripts to make password spraying attacks against Lync/S4B, OWA & O365 a lot quicker, less painful and more efficient</td>
    </tr>
    <tr>
        <td><a href="https://github.com/codewhitesec/HandleKatz">codewhitesec/HandleKatz</a></td>
        <td>PIC lsass dumper using cloned handles</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cube0x0/MiniDump">cube0x0/MiniDump</a></td>
        <td>C# Lsass parser</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cube0x0/SharpSystemTriggers">cube0x0/SharpSystemTriggers</a></td>
        <td>Collection of remote authentication triggers in C#</td>
    </tr>
    <tr>
        <td><a href="https://github.com/dafthack/MSOLSpray">dafthack/MSOLSpray</a></td>
        <td>A password spraying tool for Microsoft Online accounts (Azure/O365). The script logs if a user cred is valid, if MFA is enabled on the account, if a tenant doesn't exist, if a user doesn't exist, if the account is locked, or if the account is disabled.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/danf42/GetLsaSecrets">danf42/GetLsaSecrets</a></td>
        <td>C# implementation of Get-LSASecrets originally written in PowerShell</td>
    </tr>
    <tr>
        <td><a href="https://github.com/DanMcInerney/icebreaker">DanMcInerney/icebreaker</a></td>
        <td>Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        </td>
    </tr>
    <tr>
        <td><a href="https://github.com/deepinstinct/LsassSilentProcessExit">deepinstinct/LsassSilentProcessExit</a></td>
        <td>Command line interface to dump LSASS memory to disk via SilentProcessExit</td>
    </tr>
    <tr>
        <td><a href="https://github.com/djhohnstein/1PasswordSuite">djhohnstein/1PasswordSuite</a></td>
        <td>Utilities to extract secrets from 1Password</td>
    </tr>
    <tr>
        <td><a href="https://github.com/eladshamir/Internal-Monologue">eladshamir/Internal-Monologue</a></td>
        <td>Internal Monologue Attack: Retrieving NTLM Hashes without Touching LSASS</td>
    </tr>
    <tr>
        <td><a href="https://github.com/EspressoCake/PPLDump_BOF">EspressoCake/PPLDump_BOF</a></td>
        <td>A faithful transposition of the key features/functionality of @itm4n's PPLDump project as a BOF.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/fireeye/ADFSpoof">fireeye/ADFSpoof</a></td>
        <td>A python tool to forge AD FS security tokens.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Flangvik/BetterSafetyKatz">Flangvik/BetterSafetyKatz</a></td>
        <td>Fork of SafetyKatz that dynamically fetches the latest pre-compiled release of Mimikatz directly from
            gentilkiwi GitHub repo, runtime patches signatures and uses SharpSploit DInvoke to PE-Load into memory.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/FSecureLABS/physmem2profit">FSecureLABS/physmem2profit </a></td>
        <td>Physmem2profit can be used to create a minidump of a target hosts' LSASS process by analysing physical
            memory remotely</td>
    </tr>
    <tr>
        <td><a href="https://github.com/FSecureLABS/SharpClipHistory">FSecureLABS/SharpClipHistory</a></td>
        <td>SharpClipHistory is a .NET application written in C# that can be used to read the contents of a user's clipboard history in Windows 10 starting from the 1809 Build.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/G0ldenGunSec/SharpSecDump">G0ldenGunSec/SharpSecDump</a></td>
        <td>.Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py</td>
    </tr>
    <tr>
        <td><a href="https://github.com/GhostPack/SafetyKatz">GhostPack/SafetyKatz</a></td>
        <td>SafetyKatz is a combination of slightly modified version of @gentilkiwi's Mimikatz project and @subTee's
            .NET PE Loader</td>
    </tr>
    <tr>
        <td><a href="https://github.com/GhostPack/SharpDump">GhostPack/SharpDump</a></td>
        <td>SharpDump is a C# port of PowerSploit's Out-Minidump.ps1 functionality.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/GhostPack/Rubeus">GhostPack/Rubeus</a></td>
        <td>Rubeus is a C# toolset for raw Kerberos interaction and abusesRubeus is a C# toolset for raw Kerberos
            interaction and abuses</td>
    </tr>
    <tr>
        <td><a href="https://github.com/gitjdm/dumper2020">gitjdm/dumper2020</a></td>
        <td>Yet another LSASS dumper</td>
    </tr>
    <tr>
        <td><a href="https://github.com/G0ldenGunSec/SharpSecDump">G0ldenGunSec/SharpSecDump</a></td>
        <td>.Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py</td>
    </tr>
    <tr>
        <td><a href="https://github.com/GossiTheDog/HiveNightmare">GossiTheDog/HiveNightmare</a></td>
        <td>Exploit allowing you to read registry hives as non-admin</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Hackndo/lsassy">Hackndo/lsassy</a></td>
        <td>Extract credentials from lsass remotely</td>
    </tr>
    <tr>
        <td><a href="https://github.com/horizon3ai/vcenter_saml_login">horizon3ai/vcenter_saml_login</a></td>
        <td>A tool to extract the IdP cert from vCenter backups and log in as Administrator</td>
    </tr>
    <tr>
        <td><a href="https://github.com/HunnicCyber/SharpDomainSpray">HunnicCyber/SharpDomainSpray</a></td>
        <td>Basic password spraying tool for internal tests and red teaming</td>
    </tr>
    <tr>
        <td><a href="https://github.com/IlanKalendarov/PyHook">IlanKalendarov/PyHook</a></td>
        <td>PyHook is an offensive API hooking tool written in python designed to catch various credentials within the API call.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/IlanKalendarov/SharpHook">IlanKalendarov/SharpHook</a></td>
        <td>SharpHook is inspired by the SharpRDPThief project, It uses various API hooks in order to give us the desired credentials.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/iomoath/SharpSpray">iomoath/SharpSpray</a></td>
        <td>Active Directory password spraying tool. Auto fetches user list and avoids potential lockouts.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/itm4n/PPLdump">itm4n/PPLdump</a></td>
        <td>Dump the memory of a PPL with a userland exploit</td>
    </tr>
    <tr>
        <td><a href="https://github.com/jfmaes/SharpHandler">jfmaes/SharpHandler</a></td>
        <td>Duplicating handles to dump LSASS since 2021</td>
    </tr>
    <tr>
        <td><a href="https://github.com/jfmaes/SharpRDPDump">jfmaes/SharpRDPDump</a></td>
        <td>Create a minidump of TermService for clear text pw extraction</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Kevin-Robertson/Inveigh">Kevin-Robertson/Inveigh</a></td>
        <td>Windows PowerShell ADIDNS/LLMNR/mDNS/NBNS spoofer/man-in-the-middle tool</td>
    </tr>
    <tr>
        <td><a href="https://github.com/knavesec/CredMaster">knavesec/CredMaster</a></td>
        <td>Refactored & improved CredKing password spraying tool, uses FireProx APIs to rotate IP addresses, stay anonymous, and beat throttling</td>
    </tr>
    <tr>
        <td><a href="https://github.com/KoreLogicSecurity/wmkick">KoreLogicSecurity/wmkick</a></td>
        <td>WMkick is a TCP protocol redirector/MITM tool that targets NTLM authentication message flows in WMI (135/tcp) and Powershell-Remoting/WSMan/WinRM (5985/tcp) to capture NetNTLMv2 hashes.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/m0rv4i/SafetyDump">m0rv4i/SafetyDump</a></td>
        <td>Dump stuff without touching disk</td>
    </tr>
    <tr>
        <td><a href="https://github.com/MadHatt3R-0x90/SharpPuppet">MadHatt3R-0x90/SharpPuppet</a></td>
        <td>Tool Allowing Keystroke Injection Into Arbitrary Window.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mdsecactivebreach/Farmer">mdsecactivebreach/Farmer</a></td>
        <td>Farmer is a project for collecting NetNTLM hashes in a Windows domain. Farmer achieves this by creating a local WebDAV server that causes the WebDAV Mini Redirector to authenticate from any connecting clients.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mobdk/CopyCat">mobdk/CopyCat</a></<td>
        <td>Simple rapper for Mimikatz, bypass Defender</td>
    </tr>
    <tr>
        <td><a href="https://github.com/nidem/kerberoast">nidem/kerberoast</a></td>
        <td>Kerberoast is a series of tools for attacking MS Kerberos implementations. Below is a brief overview of what
            each tool does.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/oxfemale/LogonCredentialsSteal">oxfemale/LogonCredentialsSteal</a></td>
        <td>LOCAL AND REMOTE HOOK msv1_0!SpAcceptCredentials from LSASS.exe and DUMP DOMAIN/LOGIN/PASSWORD IN CLEARTEXT to text file.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/peewpw/Invoke-WCMDump">peewpw/Invoke-WCMDump</a></td>
        <td>PowerShell Script to Dump Windows Credentials from the Credential Manager</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Pickfordmatt/SharpLocker">Pickfordmatt/SharpLocker</a></td>
        <td>SharpLocker helps get current user credentials by popping a fake Windows lock screen, all output is sent to Console which works perfect for Cobalt Strike.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/PorLaCola25/TransactedSharpMiniDump">PorLaCola25/TransactedSharpMiniDump</a></td>
        <td>Implementation of b4rtiks's SharpMiniDump using NTFS transactions to avoid writting the minidump to disk and exfiltrating it via HTTPS using sockets.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/postrequest/safetydump">postrequest/safetydump</a></td>
        <td>MiniDump a process in memory with rust</td>
    </tr>
    <tr>
        <td><a href="https://github.com/putterpanda/mimikittenz">putterpanda/mimikittenz</a></td>
        <td>A post-exploitation powershell tool for extracting juicy info from memory.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/RedCursorSecurityConsulting/SharpHashSpray">RedCursorSecurityConsulting/SharpHashSpray</a></td>
        <td>An execute-assembly compatible tool for spraying local admin hashes on an Active Directory domain.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ricardojoserf/adfsbrute">ricardojoserf/adfsbrute</a></td>
        <td>A script to test credentials against Active Directory Federation Services (ADFS), allowing password spraying or bruteforce attacks.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ropnop/kerbrute">ropnop/kerbrute</a></td>
        <td>A tool to perform Kerberos pre-auth bruteforcing</td>
    </tr>
    <tr>
        <td><a href="https://github.com/rvrsh3ll/SharpEdge">rvrsh3ll/SharpEdge</a></td>
        <td>C# Implementation of Get-VaultCredential</td>
    </tr>
    <tr>
        <td><a href="https://github.com/rvrsh3ll/TokenTactics">rvrsh3ll/TokenTactics</a></td>
        <td>Azure JWT Token Manipulation Toolset</td>
    </tr>
    <tr>
        <td><a href="https://github.com/rvrsh3ll/SharpSMBSpray">rvrsh3ll/SharpSMBSpray</a></td>
        <td>Spray a hash via smb to check for local administrator access</td>
    </tr>
    <tr>
        <td><a href="https://github.com/S3cur3Th1sSh1t/RDPThiefInject">S3cur3Th1sSh1t/RDPThiefInject</a></td>
        <td>RDPThief donut shellcode inject into mstsc</td>
    </tr>
    <tr>
        <td><a href="https://github.com/sec-consult/aggrokatz">sec-consult/aggrokatz</a></td>
        <td>Aggrokatz is an aggressor plugin extension for Cobalt Strike which enables pypykatz to interface with the beacons remotely and allows it to parse LSASS dump files and registry hive files to extract credentials and other secrets stored without downloading the file and without uploading any suspicious code to the beacon.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/secdev-01/Mimikore">secdev-01/Mimikore</a></td>
        <td>.NET 5 Single file Application . Mimikatz or any Base64 PE Loader.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/shantanu561993/SharpLoginPrompt">shantanu561993/SharpLoginPrompt</a></td>
        <td>This Program creates a login prompt to gather username and password of the current user. This project allows red team to phish username and password of the current user without touching lsass and having adminitrator credentials on the system.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ShutdownRepo/smartbrute">ShutdownRepo/smartbrute</a></td>
        <td>Password spraying and bruteforcing tool for Active Directory Domain Services</td>
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
        <td><a href="https://github.com/swisskyrepo/SharpLAPS">swisskyrepo/SharpLAPS</a></td>
        <td>Retrieve LAPS password from LDAP</td>
    </tr>
    <tr>
        <td><a href="https://github.com/treebuilder/aad-sso-enum-brute-spray">treebuilder/aad-sso-enum-brute-spray</a></td>
        <td>POC of SecureWorks' recent Azure Active Directory password brute-forcing vuln</td>
    </tr>
    <tr>
        <td><a href="https://github.com/uknowsec/SharpDecryptPwd">uknowsec/SharpDecryptPwd</a></td>
        <td>对密码已保存在 Windwos 系统上的部分程序进行解析,包括：Navicat,TeamViewer,FileZilla,WinSCP,Xmangager系列产品（Xshell,Xftp)。</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ustayready/SharpHose">ustayready/SharpHose</a></td>
        <td>Asynchronous Password Spraying Tool in C# for Windows Environments</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Viralmaniar/Remote-Desktop-Caching-">Viralmaniar/Remote-Desktop-Caching-</a>
        </td>
        <td>This tool allows one to recover old RDP (mstsc) session information in the form of broken PNG files. These
            PNG files allows Red Team member to extract juicy information such as LAPS passwords or any sensitive
            information on the screen.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/w1u0u1/minidump">w1u0u1/minidump</a></td>
        <td>Custom implementation of DbgHelp's MiniDumpWriteDump function. Uses static syscalls to replace low-level functions like NtReadVirtualMemory.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/zcgonvh/SSMSPwd">zcgonvh/SSMSPwd</a></td>
        <td>SQL Server Management Studio(SSMS) saved password dumper</td>
    </tr>
</table>

## Lateral Movement

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/0xcpu/winsmsd">0xcpu/winsmsd</a></td>
        <td>Windows (ShadowMove) Socket Duplication</td>
    </tr>
    <tr>
        <td><a href="https://github.com/0xthirteen/MoveKit">0xthirteen/MoveKit</a></td>
        <td>Cobalt Strike kit for Lateral Movement</td>
    </tr>
    <tr>
        <td><a href="https://github.com/0xthirteen/SharpMove">0xthirteen/SharpMove</a></td>
        <td>.NET Project for performing Authenticated Remote Execution</td>
    </tr>
    <tr>
        <td><a href="https://github.com/0xthirteen/SharpRDP">0xthirteen/SharpRDP</a></td>
        <td>Remote Desktop Protocol .NET Console Application for Authenticated Command Execution</td>
    </tr>
    <tr>
        <td><a href="https://github.com/360-Linton-Lab/WMIHACKER">360-Linton-Lab/WMIHACKER</a></td>
        <td>A Bypass Anti-virus Software Lateral Movement Command Execution Tool</td>
    </tr>
    <tr>
        <td><a href="https://github.com/anthemtotheego/SharpExec">anthemtotheego/SharpExec</a></td>
        <td>SharpExec is an offensive security C# tool designed to aid with lateral movement.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/bigb0sss/Bankai">bigb0sss/Bankai</a></td>
        <td>Another Go Shellcode Loader</td>
    </tr>
    <tr>
        <td><a href="https://github.com/bohops/WSMan-WinRM">bohops/WSMan-WinRM</a></td>
        <td>A collection of proof-of-concept source code and scripts for executing remote commands over WinRM using the WSMan.Automation COM object</td>
    </tr>
    <tr>
        <td><a href="https://github.com/byt3bl33d3r/CrackMapExec">byt3bl33d3r/CrackMapExec</a></td>
        <td>A swiss army knife for pentesting networks</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cube0x0/SharpMapExec">cube0x0/SharpMapExec</a></td>
        <td>A sharpen version of CrackMapExec. This tool is made to simplify penetration testing of networks and to create a swiss army knife that is made for running on Windows which is often a requirement during insider threat simulation engagements.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cobbr/SharpSploit">cobbr/SharpSploit</a></td>
        <td>SharpSploit is a .NET post-exploitation library written in C#</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cyberark/shimit">cyberark/shimit</a></td>
        <td>A tool that implements the Golden SAML attack</td>
    </tr>
    <tr>
        <td><a href="https://github.com/DefensiveOrigins/PlumHound">DefensiveOrigins/PlumHound</a></td>
        <td>Bloodhound for Blue and Purple Teams</td>
    </tr>
    <tr>
        <td><a href="https://github.com/FuzzySecurity/StandIn">FuzzySecurity/StandIn</a></td>
        <td>StandIn is a small .NET35/45 AD post-exploitation toolkit</td>
    </tr>
    <tr>
        <td><a href="https://github.com/improsec/ImproHound">improsec/ImproHound</a></td>
        <td>Identify the attack paths in BloodHound breaking your AD tiering</td>
    </tr>
    <tr>
        <td><a href="https://github.com/infosecn1nja/SharpDoor">infosecn1nja/SharpDoor</a></td>
        <td>SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching
            termsrv.dll file.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/iomoath/SharpStrike">iomoath/SharpStrike</a></td>
        <td>SharpStrike is a post-exploitation tool written in C# that uses either CIM or WMI to query remote systems. It can use provided credentials or the current user's session.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/juliourena/SharpNoPSExec">juliourena/SharpNoPSExec</a></td>
        <td>Get file less command execution for lateral movement.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/klezVirus/CheeseTools">klezVirus/CheeseTools</a></td>
        <td>Self-developed tools for Lateral Movement/Code Execution</td>
    </tr>
    <tr>
        <td><a href="https://github.com/knavesec/Max">knavesec/Max</a></td>
        <td>Maximizing BloodHound. Max is a good boy.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mez-0/winrmdll">mez-0/winrmdll</a></td>
        <td>C++ WinRM API via Reflective DLL</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Mr-Un1k0d3r/SCShell">Mr-Un1k0d3r/SCShell</a></td>
        <td>Fileless lateral movement tool that relies on ChangeServiceConfigA to run command</td>
    </tr>
    <tr>
        <td><a href="https://github.com/netero1010/ServiceMove-BOF">netero1010/ServiceMove-BOF</a></td>
        <td>New lateral movement technique by abusing Windows Perception Simulation Service to achieve DLL hijacking code execution.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/RiccardoAncarani/LiquidSnake">RiccardoAncarani/LiquidSnake</a></td>
        <td>LiquidSnake is a tool that allows operators to perform fileless lateral movement using WMI Event Subscriptions and GadgetToJScript</td>
    </tr>
    <tr>
        <td><a href="https://github.com/RiccardoAncarani/TaskShell">RiccardoAncarani/TaskShell</a></td>
        <td>TaskShell</td>
    </tr>
    <tr>
        <td><a href="https://github.com/rvrsh3ll/SharpCOM">rvrsh3ll/SharpCOM</a></td>
        <td>SharpCOM is a c# port of Invoke-DCOM</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ScorpionesLabs/DVS">ScorpionesLabs/DVS</a></td>
        <td>D(COM) V(ulnerability) S(canner) AKA Devious swiss army knife - Lateral movement using DCOM Objects</td>
    </tr>
    <tr>
        <td><a href="https://github.com/tothi/rbcd-attack">tothi/rbcd-attack</a></td>
        <td>Kerberos Resource-Based Constrained Delegation Attack from Outside using Impacket</td>
    </tr>
    <tr>
        <td><a href="https://gitlab.com/theepicpowner/dcom_av_exec">theepicpowner/dcom_av_exec</a></td>
        <td>DCOM_AV_EXEC allows for "diskless" lateral movement to a target on the same network via DCOM. The AV_Bypass_Framework_V3 creates a .NET shellcode runner (output as DLL) which can be used with the DCOM_AV_EXEC tool to bypass antivirus solutions like Microsoft Defender as all shellcode is AES encrypted and executed in memory.</td>
    </tr>
</table>

## Collection

<table>
    <tr>
        <td><b>Link</b></td>
        <td><b>Description</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/cisp/GetMail">cisp/GetMail</a></td>
        <td>利用NTLM Hash读取Exchange邮件</td>
    </tr>
    <tr>
        <td><a href="https://github.com/djhohnstein/SharpChromium">djhohnstein/SharpChromium</a></td>
        <td>.NET 4.0 CLR Project to retrieve Chromium data, such as cookies, history and saved logins.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/OG-Sadpanda/SharpExcelibur">OG-Sadpanda/SharpExcelibur</a></td>
        <td>Read Excel Spreadsheets (XLS/XLSX) using Cobalt Strike's Execute-Assembly</td>
    </tr>
    <tr>
        <td><a href="https://github.com/OG-Sadpanda/SharpSword">OG-Sadpanda/SharpSword</a></td>
        <td>Read the contents of DOCX files using Cobalt Strike's Execute-Assembly</td>
    </tr>
    <tr>
        <td><a href="https://github.com/seastorm/PuttyRider">seastorm/PuttyRider</a></td>
        <td>Hijack Putty sessions in order to sniff conversation and inject Linux commands.</td>
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
        <td>It is developed using .net core framework in C# language. Allows operators to leverage O365 services for
            establishing command & control communication channel. It usages Microsoft Graph APIs for communicating with
            O365 services.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ahmedkhlief/Ninja">ahmedkhlief/Ninja</a></td>
        <td>Open source C2 server created for stealth red team operations</td>
    </tr>
    <tr>
        <td><a href="https://github.com/bashexplode/cs2webconfig">bashexplode/cs2webconfig</a></td>
        <td>Convert Cobalt Strike profiles to IIS web.config files</td>
    </tr>
    <tr>
        <td><a href="https://github.com/bats3c/shad0w">bats3c/shad0w</a></td>
        <td>SHAD0W is a modular C2 framework designed to successfully operate on mature environments.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/blackbotinc/Atomic-Red-Team-Intelligence-C2">blackbotinc/Atomic-Red-Team-Intelligence-C2</a></td>
        <td>ARTi-C2 is a post-exploitation framework used to execute Atomic Red Team test cases with rapid payload deployment and execution capabilities via .NET's DLR.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/boku7/azureOutlookC2">boku7/azureOutlookC2</a></td>
        <td>Azure Outlook Command & Control (C2) - Remotely control a compromised Windows Device from your Outlook mailbox. Threat Emulation Tool for North Korean APT InkySquid / ScarCruft / APT37. TTP: Use Microsoft Graph API for C2 Operations.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/byt3bl33d3r/SILENTTRINITY">byt3bl33d3r/SILENTTRINITY</a></td>
        <td>An asynchronous, collaborative post-exploitation agent powered by Python and .NET's DLR</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cedowens/C2_Cradle">cedowens/C2_Cradle</a></td>
        <td>Tool to download, install, and run macOS capable command & control servers (i.e., C2s with macOS payloads/clients) as docker containers from a list of options. This is helpful for automating C2 server setup.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cobbr/C2Bridge">cobbr/C2Bridge</a></td>
        <td>C2Bridges allow developers to create new custom communication protocols and quickly utilize them within Covenant.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cobbr/Covenant">cobbr/Covenant</a></td>
        <td> Covenant is a .NET command and control framework that aims to highlight the attack surface of .NET, make
            the use of offensive .NET tradecraft easier, and serve as a collaborative command and control platform for
            red teamers.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Cr4sh/MicroBackdoor">Cr4sh/MicroBackdoor</a></td>
        <td>Small and convenient C2 tool for Windows targets</td>
    </tr>
    <tr>
        <td><a href="https://github.com/cyberark/kubesploit">cyberark/kubesploit</a></td>
        <td>Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in Golang, focused on containerized environments.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/DeimosC2/DeimosC2">DeimosC2/DeimosC2</a></td>
        <td>DeimosC2 is a Golang command and control framework for post-exploitation.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/EspressoCake/Cobalt_Strike_Ansible">EspressoCake/Cobalt_Strike_Ansible</a></td>
        <td>A project to replicate the functionality of Noah Powers' ServerSetup script, but with error handling and fixed Namecheap API support.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/fbkcs/ThunderDNS">fbkcs/ThunderDNS</a></td>
        <td>This tool can forward TCP traffic over DNS protocol. Non-compile clients + socks5 support.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Flangvik/AzureC2Relay">Flangvik/AzureC2Relay</a></td>
        <td>AzureC2Relay is an Azure Function that validates and relays Cobalt Strike beacon traffic by verifying the incoming requests based on a Cobalt Strike Malleable C2 profile.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/geemion/Khepri">geemion/Khepri</a></td>
        <td>🔥🔥🔥Free,Open-Source,Cross-platform agent and Post-exploiton tool written in Golang and C++, the architecture and usage like Cobalt Strike</td>
    </tr>
    <tr>
        <td><a href="https://github.com/gl4ssesbo1/Nebula">gl4ssesbo1/Nebula</a></td>
        <td>Cloud C2 Framework, which at the moment offers reconnaissance, enumeration, exploitation, post exploitation on AWS, but still working to allow testing other Cloud Providers and DevOps Components.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/its-a-feature/Mythic">its-a-feature/Mythic</a></td>
        <td>A collaborative, multi-platform, red teaming framework</td>
    </tr>
    <tr>
        <td><a href="https://github.com/kgretzky/pwndrop">kgretzky/pwndrop</a></td>
        <td>Self-deployable file hosting service for red teamers, allowing to easily upload and share payloads over HTTP and WebDAV.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/leonjza/tc2">leonjza/tc2</a></td>
        <td>Treafik fronted c2 examples</td>
    </tr>
    <tr>
        <td><a href="https://github.com/loseys/BlackMamba">loseys/BlackMamba</a></td>
        <td>BlackMamba is a multi client C2/post exploitation framework with some spyware features. Powered by Python 3.8.6 and QT Framework.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mgeeky/RedWarden">mgeeky/RedWarden</a></td>
        <td>Cobalt Strike C2 Reverse proxy that fends off Blue Teams, AVs, EDRs, scanners through packet inspection and malleable profile correlation</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mhaskar/DNSStager">mhaskar/DNSStager</a></td>
        <td>DNSStager is an open-source project based on Python used to hide and transfer your payload using DNS.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mhaskar/Octopus">mhaskar/Octopus</a></td>
        <td>Open source pre-operation C2 server based on python and powershell</td>
    </tr>
    <tr>
        <td><a href="https://github.com/MythicAgents/hermes">MythicAgents/hermes</a></td>
        <td>Swift 5 macOS implant</td>
    </tr>
    <tr>
        <td><a href="https://github.com/NetSPI/SQLC2">NetSPI/SQLC2</a></td>
        <td>SQLC2 is a PowerShell script for deploying and managing a command and control system that uses SQL Server as both the control server and the agent.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/nettitude/SharpSocks">nettitude/SharpSocks</a></td>
        <td>Tunnellable HTTP/HTTPS socks4a proxy written in C# and deployable via PowerShell</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Ne0nd0g/merlin">Ne0nd0g/merlin</a></td>
        <td>Merlin is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in golang.
        </td>
    </tr>
    <tr>
        <td><a href="https://github.com/p3nt4/Nuages">p3nt4/Nuages</a></td>
        <td>A modular C2 framework</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Porchetta-Industries/pyMalleableC2">Porchetta-Industries/pyMalleableC2</a></td>
        <td>Python interpreter for Cobalt Strike Malleable C2 Profiles. Allows you to parse, build and modify them programmatically.</td>
    </tr>
    <tr>
        <td><a href="http://prismatica.io/">Project Prismatica</a></td>
        <td>Project Prismatica is a focused framework for Command and Control that is dedicated to extensibility.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/pucarasec/zuthaka">pucarasec/zuthaka</a></td>
        <td>Zuthaka is an open source application designed to assist red-teaming efforts, by simplifying the task of managing different APTs and other post-exploitation tools.</td>
    </tr>
        <tr>
            <td><a href="https://github.com/r3nhat/GRAT2">r3nhat/GRAT2</a></td>
            <td>GRAT2 is a Command and Control (C2) tool written in python3 and the client in .NET 4.5</td>
        </tr>
    <tr>
        <td><a href="https://github.com/sensepost/godoh">sensepost/goDoH</a></td>
        <td>godoh - A DNS-over-HTTPS C2</td>
    </tr>
    <tr>
        <td><a href="https://github.com/SpiderLabs/DoHC2">SpiderLabs/DoHC2</a></td>
        <td>DoHC2 allows the ExternalC2 library from Ryan Hanson (https://github.com/ryhanson/ExternalC2) to be
            leveraged for command and control (C2) via DNS over HTTPS (DoH).</td>
    </tr>
    <tr>
        <td><a href="https://github.com/threatexpress/mythic2modrewrite">threatexpress/mythic2modrewrite</a></td>
        <td>Generate Apache mod_rewrite rules for Mythic C2 profiles</td>
    </tr>
    <tr>
        <td><a href="https://github.com/threatexpress/random_c2_profile">threatexpress/random_c2_profile</a></td>
        <td>Cobalt Strike random C2 Profile generator</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Tylous/SourcePoint">Tylous/SourcePoint</a></td>
        <td>SourcePoint is a C2 profile generator for Cobalt Strike command and control servers designed to ensure evasion.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/vestjoe/cobaltstrike_services">vestjoe/cobaltstrike_services</a></td>
        <td>Running Cobalstrike Teamserver as a Service</td>
    </tr>
    <tr>
        <td><a href="https://github.com/X-C3LL/wfp-reader">X-C3LL/wfp-reader</a></td>
        <td>Proof of concept - Covert Channel using Windows Filtering Platform (C#)</td>
    </tr>
    <tr>
        <td><a href="https://github.com/zerosum0x0/koadic">zerosum0x0/koadic</a></td>
        <td>Koadic C3 COM Command & Control - JScript RAT</td>
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
        <td><a href="https://github.com/Flangvik/SharpExfiltrate">Flangvik/SharpExfiltrate</a></td>
        <td>Modular C# framework to exfiltrate loot over secure and trusted channels.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/hackerschoice/gsocket">hackerschoice/gsocket</a></td>
        <td>Global Socket. Moving data from here to there. Securely, Fast and trough NAT/Firewalls</td>
    </tr>
    <tr>
        <td><a href="https://github.com/hackerschoice/gs-transfer">hackerschoice/gs-transfer</a></td>
        <td>Secure File Transfer via Global Socket Bounce Network</td>
    </tr>
    <tr>
        <td><a href="https://github.com/m57/dnsteal">m57/dnsteal</a></td>
        <td>DNS Exfiltration tool for stealthily sending files over DNS requests.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mdsecactivebreach/RegistryStrikesBack">mdsecactivebreach/RegistryStrikesBack</a>
        </td>
        <td>RegistryStrikesBack allows a red team operator to export valid .reg files for portions of the Windows
            Registry via a .NET assembly that should run as a standard user. It can be useful in exfiltrating config
            files such as to support actions like are described in the "Segmentation Vault" article on the MDSec Blog.
        </td>
    </tr>
    <tr>
        <td><a href="https://github.com/pentestpartners/PTP-RAT">pentestpartners/PTP-RAT</a></td>
        <td>Exfiltrate data over screen interfaces. <a href="https://www.pentestpartners.com/security-blog/exfiltration-by-encoding-data-in-pixel-colour-values/">For
                more information.</a></td>
    </tr>
    <tr>
        <td><a href="https://github.com/sensepost/DET">sensepost/DET</a></td>
        <td>DET (is provided AS IS), is a proof of concept to perform Data Exfiltration using either single or multiple
            channel(s) at the same time.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/SySS-Research/Seth">SySS-Research/Seth</a></td>
        <td>Perform a MitM attack and extract clear text credentials from RDP connections</td>
    </tr>
    <tr>
        <td><a href="https://github.com/veggiedefender/browsertunnel">veggiedefender/browsertunnel</a></td>
        <td>Surreptitiously exfiltrate data from the browser over DNS</td>
    </tr>
    <tr>
        <td><a href="https://github.com/vp777/procrustes">vp777/procrustes</a></td>
        <td>A bash script that automates the exfiltration of data over dns in case we have a blind command execution on
            a server where all outbound connections except DNS are blocked.</td>
    </tr>
</table>
