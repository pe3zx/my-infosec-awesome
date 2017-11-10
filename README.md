# My Awesome

[![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)
[![travis-banner](https://travis-ci.org/pe3zx/my-awesome.svg?branch=master)](https://travis-ci.org/pe3zx/my-awesome)

My curated list of awesome links, resources and tools

- [My Awesome](#my-awesome)
- [Articles](#article)
- [Tools](#tools)
	- [AWS Security](#aws-security)
    - [Binary Analysis](#binary-analysis)
    - [Digital Forensics and Incident Response](#digital-forensics-and-incident-response)
    - [Exploits](#exploits)

---

## Articles

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
        <td>
            <a href="https://github.com/fireeye/flare-floss">fireeye/flare-floss</a>
        </td>
        <td>
            FireEye Labs Obfuscated String Solver - Automatically extract obfuscated strings from malware.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/katjahahn/PortEx" target="_blank">katjahahn/PortEx</a>
        </td>
        <td>
            Java library to analyse Portable Executable files with a special focus on malware analysis and PE malformation robustness
        </td>
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

### Digital Forensics and Incident Response

*Open source projects related to DFIR topic.*

<table>
    <tr>
        <td>
            <a href="https://github.com/Invoke-IR/PowerForensics">Invoke-IR/PowerForensics</a>
        </td>
        <td>
            PowerForensics provides an all in one platform for live disk forensic analysis
        </td>
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
        <td><a href="https://github.com/FriendsOfPHP/security-advisories">FriendsOfPHP/security-advisories</a></td>
        <td>The PHP Security Advisories Database references known security vulnerabilities in various PHP projects and libraries. This database must not serve as the primary source of information for security issues, it is not authoritative for any referenced software, but it allows to centralize information for convenience and easy consumption.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/IOActive/I-know-where-your-page-lives">IOActive/I-know-where-your-page-lives</a></td>
        <td><b>CVE-2016-7255</b> The kernel-mode drivers in Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, Windows 10 Gold, 1511, and 1607, and Windows Server 2016 allow local users to gain privileges via a crafted application, aka "Win32k Elevation of Privilege Vulnerability."</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ojasookert/CVE-2017-0785">ojasookert/CVE-2017-0785</a></td>
        <td><b>CVE-2017-0785</b>: A information disclosure vulnerability in the Android system (bluetooth). Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID: A-63146698.</td>
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
        <td><a href="https://github.com/victims/victims-cve-db">victims/victims-cve-db</a></td>
        <td>This database contains information regarding CVE(s) that affect various language modules. We currently store version information corresponding to respective modules as understood by select sources.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/xairy/kernel-exploits"xairy/kernel-exploits></a></td>
        <td>A bunch of proof-of-concept exploits for the Linux kernel</td>
    </tr>
</table>
