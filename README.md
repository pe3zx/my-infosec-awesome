# My Awesome

[![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)
[![travis-banner](https://travis-ci.org/pe3zx/my-awesome.svg?branch=master)](https://travis-ci.org/pe3zx/my-awesome)

My curated list of awesome links, resources and tools

- [My Awesome](#my-awesome)
- [Articles](#article)
    - [Anti Forensics](#anti-forensics)
    - [Digital Forensics and Incident Response](#digital-forensics-and-incident-response)
    - [Exploitation](#exploitation)
    - [Malware Analysis](#malware-analysis)
    - [Mobile Security](#mobile-security-1)
    - [Post Exploitation](#post-exploitation)
    - [Reverse Engineering](#reverse-engineering)
    - [Tutorials](#tutorials)
    - [Web Application Security](#web-application-security)
- [Tools](#tools)
	- [AWS Security](#aws-security)
    - [Binary Analysis](#binary-analysis)
    - [Cryptography](#cryptography)
    - [Data Exfiltration](#data-exfiltration)
    - [Digital Forensics and Incident Response](#digital-forensics-and-incident-response-1)
    - [Exploits](#exploits)
    - [Malware Analysis](#malware-analysis-1)
    - [Mobile Securtiy](#mobile-security)
    - [Network](#network)
    - [Plugins](#plugins)
    - [Privacy](#privacy)
    - [Simulation](#simulation)
    - [Social Engineering](#social-engineering)
    - [Vulnerable](#vulnerable)
    - [Web Application Security](#web-application-security-1)
    - [Windows](#windows)

---

## Articles

### Anti Forensics

- [Removing Your PDF Metadata & Protecting PDF Files](https://blog.joshlemon.com.au/protecting-your-pdf-files-and-metadata/)
    - `exiftool`, `qpdf` and `pdfinfo` are required before running [script](files/anti-forensics/removing-your-metadata-and-protecting-pdf-files.sh)

---

### Digital Forensics and Incident Response

- [A Newbie’s Guide to ESXi and VM Log Files](https://www.altaro.com/vmware/introduction-esxi-vm-log-files/)
- [certsocietegenerale/IRM - Incident Response Methodologies](https://github.com/certsocietegenerale/IRM)
- [Tool Analysis Result Sheet](https://jpcertcc.github.io/ToolAnalysisResultSheet/)

#### Unix/Linux

- [Bruteforcing Linux Full Disk Encryption (LUKS) with hashcat - The Forensic way!](https://blog.pnb.io/2018/02/bruteforcing-linux-full-disk-encryption.html)
- [Can an SSH session be taken from memory?](https://security.stackexchange.com/questions/148082/can-an-ssh-session-be-taken-from-memory)
- [INTRO TO LINUX FORENSICS](https://countuponsecurity.com/2017/04/12/intro-to-linux-forensics/)
- [Linux Memory Forensics: Dissecting the User Space Process Heap](https://articles.forensicfocus.com/2017/10/16/linux-memory-forensics-dissecting-the-user-space-process-heap/)
- [KIT-CERT Checklist for Linux Forensics](https://git.scc.kit.edu/KIT-CERT/Linux-Forensics-Checklist/blob/master/Linux-Forensics-Checklist.md)

#### IoT

- [Internet Of Things Mobility Forensics](https://articles.forensicfocus.com/2017/05/17/internet-of-things-mobility-forensics/)

#### MacOS/iOS

- [How to Acquire an iOS 11 Device Without the PIN/Passcode](https://www.magnetforensics.com/blog/how-to-acquire-an-ios-11-device-without-the-pinpasscode/)
- [Live Forensic Acquisition From Mac Computers](http://www.computerpi.com/live-forensic-acquisition-from-mac-computers/)
- [iOS 11: HEVC and HEIF (heic) files](https://www.cclgroupltd.com/ios-11-hevc-heif-heic-files/)
- [macOS Unified log: 1 why, what and how](https://eclecticlight.co/2018/03/19/macos-unified-log-1-why-what-and-how/)
- [macOS Unified log: 2 content and extraction](https://eclecticlight.co/2018/03/20/macos-unified-log-2-content-and-extraction/)
- [macOS Unified log: 3 finding your way](https://eclecticlight.co/2018/03/21/macos-unified-log-3-finding-your-way/)
- [Monkey takes a .heic](http://cheeky4n6monkey.blogspot.com/2017/10/monkey-takes-heic.html)
- [Mounting an APFS image in Linux](http://az4n6.blogspot.com/2018/01/mounting-apfs-image-in-linux.html)
- [Reading Notes database on macOS](https://www.swiftforensics.com/2018/02/reading-notes-database-on-macos.html)
- [The Hitchhiker’s Guide to macOS USB Forensics](http://cyberforensicator.com/2017/11/06/the-hitchhikers-guide-to-macos-usb-forensics/)
- [There’s Gold In Them There Blobs!](https://www.ciofecaforensics.com/2017/10/13/theres-gold-in-them-there-blobs/)

#### Windows

- [(Am)cache still rules everything around me (part 2 of 1)](https://binaryforay.blogspot.com/2017/10/amcache-still-rules-everything-around.html)
- [Amcache and Shimcache in forensic analysis](https://andreafortuna.org/amcache-and-shimcache-in-forensic-analysis-8e55aa675d2f)
- [Automating large-scale memory forensics](https://medium.com/@henrikjohansen/automating-large-scale-memory-forensics-fdc302dc3383)
- [Carving EVTX](https://rawsec.lu/blog/posts/2017/Jun/23/carving-evtx/)
- [Certificate Chain Cloning and Cloned Root Trust Attacks](https://posts.specterops.io/code-signing-certificate-cloning-attacks-and-defenses-6f98657fc6ec)
- [Detecting DDE in MS Office documents with YARA rules](https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/)
- [Forensic Analysis of Systems that have Windows Subsystem for Linux Installed](http://blog.1234n6.com/2017/10/forensic-analysis-of-systems-with.html)
- [Getting to the Bottom of CVE-2018-0825 Heap Overflow Buffer](https://www.ixiacom.com/company/blog/getting-bottom-cve-2018-0825-heap-overflow-buffer)
- [Hidden Treasure: Intrusion Detection with ETW (Part 1)](https://blogs.technet.microsoft.com/office365security/hidden-treasure-intrusion-detection-with-etw-part-1/)
- [How to Crack Passwords for Password Protected MS Office Documents](https://www.blackhillsinfosec.com/crack-passwords-password-protected-ms-office-documents/)
- [HUNTING EVENT LOGGING COVERUP](http://malwarenailed.blogspot.com/2017/10/update-to-hunting-mimikatz-using-sysmon.html)
- [Logging Keystrokes with Event Tracing for Windows (ETW)](https://www.cyberpointllc.com/srt/posts/srt-logging-keystrokes-with-event-tracing-for-windows-etw.html)
- [Looking at APT28 latest Talos Security write up and how YOU could catch this type of behavior](https://hackerhurricane.blogspot.com/2017/10/looking-at-apt28-latest-talos-security.html)
- [MAC(b) times in Windows forensic analysis](https://andreafortuna.org/mac-b-times-in-windows-forensics-analysis-c821d801a810)
- [Memory Acquisition and Virtual Secure Mode](https://df-stream.com/2017/08/memory-acquisition-and-virtual-secure/)
- [pwndizzle/CodeExecutionOnWindows - A list of ways to execute code on Windows using legitimate Windows tools](https://github.com/pwndizzle/CodeExecutionOnWindows)
- [RecentApps Registry Key](https://df-stream.com/2017/10/recentapps/)
- [Some reminders about Windows file times](https://medium.com/@4n68r/some-reminders-about-windows-file-times-2debe1edb978)
- [Tales of a Threat Hunter 1](https://www.eideon.com/2017-09-09-THL01-Mimikatz/)
- [Volume Shadow Copies in forensic analysis](https://andreafortuna.org/volume-shadow-copies-in-forensics-analysis-7708adefe61c)
- [Use Windows Event Forwarding to help with intrusion detection](https://docs.microsoft.com/en-us/windows/threat-protection/use-windows-event-forwarding-to-assist-in-instrusion-detection)
- [Windows, Now with built in anti forensics!](http://www.hecfblog.com/2017/04/windows-now-built-in-anti-forensics.html)
- [Windows Credentials: Attack + Mitigation + Defense](https://www.first.org/resources/papers/conf2017/Windows-Credentials-Attacks-and-Mitigation-Techniques.pdf)
- [Windows Drive Acquisition](https://articles.forensicfocus.com/2017/10/19/windows-drive-acquisition/)
- [Windows event logs in forensic analysis](https://andreafortuna.org/windows-event-logs-in-forensic-analysis-d80e2a134fdd)
- [Windows Privileged Access Reference](https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access-reference-material#ATLT_BM)
- [Windows registry in forensic analysis](https://andreafortuna.org/windows-registry-in-forensic-analysis-7bf060d2da)
- [Windows Security Identifiers (SIDs)](https://andreafortuna.org/windows-security-identifiers-sids-2196a5be2f4d)
- [Windows Subsystem for Linux and Forensic Analysi](http://blog.1234n6.com/2017/10/windows-subsystem-for-linux-and.html)
- [Windows Event Forwarding for Network Defense](https://medium.com/@palantir/windows-event-forwarding-for-network-defense-cb208d5ff86f)

---

### Exploitation

- [Guest Diary (Etay Nir) Kernel Hooking Basics](https://isc.sans.edu/forums/diary/Guest+Diary+Etay+Nir+Kernel+Hooking+Basics/23155/)

#### Platform: Android

- [Android Bluetooth Vulnerabilities in the March 2018 Security Bulletin](https://blog.quarkslab.com/android-bluetooth-vulnerabilities-in-the-march-2018-security-bulletin.html)
- [CVE-2017-13253: Buffer overflow in multiple Android DRM services](https://blog.zimperium.com/cve-2017-13253-buffer-overflow-multiple-android-drm-services/)

#### Platform: ARM

- [ARM exploitation for IoT – Episode 1](https://quequero.org/2017/07/arm-exploitation-iot-episode-1/)
- [ARM exploitation for IoT – Episode 2](https://quequero.org/2017/09/arm-exploitation-iot-episode-2/)
- [ARM exploitation for IoT – Episode 3](https://quequero.org/2017/11/arm-exploitation-iot-episode-3/)

#### Platform: Linux

- [64-bit Linux Return-Oriented Programming](https://crypto.stanford.edu/~blynn/rop/)
- [Adapting the POC for CVE-2017-1000112 to Other Kernels](http://ricklarabee.blogspot.ch/2017/12/adapting-poc-for-cve-2017-1000112-to.html)
- [Blocking double-free in Linux kernel](http://blog.ptsecurity.com/2017/08/linux-block-double-free.html)
- [CVE-2016-2384: exploiting a double-free in the usb-midi linux kernel driver](https://xairy.github.io/blog/2016/cve-2016-2384)
- [CVE-2017-2636: exploit the race condition in the n_hdlc Linux kernel driver bypassing SMEP](https://a13xp0p0v.github.io/2017/03/24/CVE-2017-2636.html)
- [Dirty COW and why lying is bad even if you are the Linux kernel](https://chao-tic.github.io/blog/2017/05/24/dirty-cow)
- [Enumeration for Linux Privilege Escalation](https://0x00sec.org/t/enumeration-for-linux-privilege-escalation/1959)
- [Escaping Docker container using waitid() – CVE-2017-5123](https://www.twistlock.com/2017/12/27/escaping-docker-container-using-waitid-cve-2017-5123/)
- [Exploiting the Linux kernel via packet sockets](https://googleprojectzero.blogspot.com/2017/05/exploiting-linux-kernel-via-packet.html)
- [Kernel Exploitation | Dereferencing a NULL pointer!](https://0x00sec.org/t/kernel-exploitation-dereferencing-a-null-pointer/3850)
- [Linux (x86) Exploit Development Series](https://sploitfun.wordpress.com/2015/06/26/linux-x86-exploit-development-tutorial-series/)
- [Linux Heap Exploitation Intro Series: The magicians cape – 1 Byte Overflow](https://sensepost.com/blog/2017/linux-heap-exploitation-intro-series-the-magicians-cape-1-byte-overflow/)
- [Linux Heap Exploitation Intro Series: Set you free() – part 1](https://sensepost.com/blog/2018/linux-heap-exploitation-intro-series-set-you-free-part-1/)
- [Linux Heap Exploitation Intro Series: Used and Abused – Use After Free](https://sensepost.com/blog/2017/linux-heap-exploitation-intro-series-used-and-abused-use-after-free/)
- [Linux Kernel ROP - Ropping your way to # (Part 1)](https://www.trustwave.com/Resources/SpiderLabs-Blog/Linux-Kernel-ROP---Ropping-your-way-to---(Part-1)/)
- [Linux Kernel ROP - Ropping your way to # (Part 2)](https://www.trustwave.com/Resources/SpiderLabs-Blog/Linux-Kernel-ROP---Ropping-your-way-to---(Part-2)/)
- [Linux Kernel Vulnerability Can Lead to Privilege Escalation: Analyzing CVE-2017-1000112](https://securingtomorrow.mcafee.com/mcafee-labs/linux-kernel-vulnerability-can-lead-to-privilege-escalation-analyzing-cve-2017-1000112/#sf118405156)
- [Linux System Call Table](http://thevivekpandey.github.io/posts/2017-09-25-linux-system-calls.html)
- [Reversing DirtyC0W](http://blog.tetrane.com/2017/09/dirtyc0w-1.html)
- [The Definitive Guide to Linux System Calls](https://blog.packagecloud.io/eng/2016/04/05/the-definitive-guide-to-linux-system-calls/)
- [xairy/linux-kernel-exploitation](https://github.com/xairy/linux-kernel-exploitation)

#### Platform: Windows

- [0patching the "Immortal" CVE-2017-7269](https://0patch.blogspot.com/2017/03/0patching-immortal-cve-2017-7269.html)
- [15 Ways to Bypass the PowerShell Execution Policy](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [A Bug Has No Name: Multiple Heap Buffer Overflows In the Windows DNS Client](https://www.bishopfox.com/blog/2017/10/a-bug-has-no-name-multiple-heap-buffer-overflows-in-the-windows-dns-client/)
- [Abusing A Writable Windows Service](https://blog.didierstevens.com/2017/09/05/abusing-a-writable-windows-service/)
- [Abusing Delay Load DLLs for Remote Code Injection](http://hatriot.github.io/blog/2017/09/19/abusing-delay-load-dll/)
- [Abusing GDI objects: Bitmap object’s size in the kernel pool](http://theevilbit.blogspot.com/2017/10/abusing-gdi-objects-bitmap-objects-size.html)
- [A deeper look at ms11-058](https://blog.skullsecurity.org/2011/a-deeper-look-at-ms11-058)
- [An Inside Look at CVE-2017-0199 – HTA and Scriptlet File Handler Vulnerability](https://blog.fortinet.com/2017/06/05/an-inside-look-at-cve-2017-0199-hta-and-scriptlet-file-handler-vulnerability)
- [Analysis of CVE-2017-11882 Exploit in the Wild](https://researchcenter.paloaltonetworks.com/2017/12/unit42-analysis-of-cve-2017-11882-exploit-in-the-wild/)
- [AtomBombing: Brand New Code Injection for Windows](https://breakingmalware.com/injection-techniques/atombombing-brand-new-code-injection-for-windows/)
- [AtomBombing CFG Protected Processes](https://breakingmalware.com/injection-techniques/atombombing-cfg-protected-processes/)
- [Breaking backwards compatibility: a 5 year old bug deep within Windows](http://www.triplefault.io/2017/07/breaking-backwards-compatibility-5-year.html)
- [Breaking out of Restricted Windows Environment](https://weirdgirlweb.wordpress.com/2017/06/14/first-blog-post/)
- [Bringing Call Gates Back](http://www.alex-ionescu.com/?p=340)
- [Bypassing Microsoft's Patch for CVE-2017-0199](http://justhaifei1.blogspot.com.br/2017/07/bypassing-microsofts-cve-2017-0199-patch.html)
- [C# Inject a Dll into a Process (w/ CreateRemoteThread)](http://www.codingvision.net/miscellaneous/c-inject-a-dll-into-a-process-w-createremotethread)
- [Decrement Windows kernel for fun and profit](https://sww-it.ru/2018-01-29/1532)
- [DEFEATING DEVICE GUARD: A LOOK INTO CVE-2017-0007](https://enigma0x3.net/2017/04/03/defeating-device-guard-a-look-into-cve-2017-0007/)
- [Detecting and mitigating elevation-of-privilege exploit for CVE-2017-0005](https://blogs.technet.microsoft.com/mmpc/2017/03/27/detecting-and-mitigating-elevation-of-privilege-exploit-for-cve-2017-0005/)
- [Digging Into a Windows Kernel Privilege Escalation Vulnerability: CVE-2016-7255](https://securingtomorrow.mcafee.com/mcafee-labs/digging-windows-kernel-privilege-escalation-vulnerability-cve-2016-7255/)
- [Disarming EMET 5.52: Controlling it all with a single write action](https://blog.ropchain.com/2017/04/03/disarming-emet-5-52/)
- [Enumerating process, thread, and image load notification callback routines in Windows](http://www.triplefault.io/2017/09/enumerating-process-thread-and-image.html)
- [EternalBlue – Everything there is to know](https://research.checkpoint.com/eternalblue-everything-know/)
- [Exploit Kit Rendezvous and CVE-2017-0022](https://0patch.blogspot.com/2017/09/exploit-kit-rendezvous-and-cve-2017-0022.html)
- [Exploiting MS16-145: MS Edge TypedArray.sort Use-After-Free (CVE-2016-7288)](https://blog.quarkslab.com/exploiting-ms16-145-ms-edge-typedarraysort-use-after-free-cve-2016-7288.html)
- [Exploiting MS16-098 RGNOBJ Integer Overflow on Windows 8.1 x64 bit by abusing GDI objects](https://sensepost.com/blog/2017/exploiting-ms16-098-rgnobj-integer-overflow-on-windows-8.1-x64-bit-by-abusing-gdi-objects/)
- [Exploring Windows virtual memory management](http://www.triplefault.io/2017/08/exploring-windows-virtual-memory.html)
- [From Out Of Memory to Remote Code Execution](https://speakerdeck.com/yukichen/from-out-of-memory-to-remote-code-execution)
- [Getting Code Execution on Windows by Abusing Default Kernel Debugging Setting](https://tyranidslair.blogspot.com/2017/03/getting-code-execution-on-windows-by.html)
- [Hardening Windows 10 with zero-day exploit mitigations](https://blogs.technet.microsoft.com/mmpc/2017/01/13/hardening-windows-10-with-zero-day-exploit-mitigations/)
- [Inject All the Things](http://blog.deniable.org/blog/2017/07/16/inject-all-the-things/)
- [Introduction to IA-32e hardware paging](http://www.triplefault.io/2017/07/introduction-to-ia-32e-hardware-paging.html)
- [Introduction to Windows Kernel Driver Exploitation (Pt. 1) - Environment Setup](https://glennmcgui.re/introduction-to-windows-kernel-exploitation-pt-1/)
- [Introduction to Windows Kernel Driver Exploitation (Pt. 2) - Stack Buffer Overflow to System Shell](https://glennmcgui.re/introduction-to-windows-kernel-driver-exploitation-pt-2/)
- [Introduction to Windows shellcode development – Part 1](https://securitycafe.ro/2015/10/30/introduction-to-windows-shellcode-development-part1/)
- [Introduction to Windows shellcode development – Part 2](https://securitycafe.ro/2015/12/14/introduction-to-windows-shellcode-development-part-2/)
- [Introduction to Windows shellcode development – Part 3](https://securitycafe.ro/2016/02/15/introduction-to-windows-shellcode-development-part-3/) 
- [Kernel Debugging 101 – Part1](https://vvalien1.wordpress.com/2016/12/26/kernel-debugging-101/)
- [Kernel Debugging 101 – Part2](https://vvalien1.wordpress.com/2017/01/01/kernel-debugging-101-part2/)
- [Kernel Debugging 101 – Part3](https://vvalien1.wordpress.com/2017/01/01/kernel-debugging-101-part3/)
- [Kernel Exploitation Case Study - "Wild" Pool Overflow on Win10 x64 RS2 (CVE-2016-3309 Reloaded)](https://siberas.de/blog/2017/10/05/exploitation_case_study_wild_pool_overflow_CVE-2016-3309_reloaded.html)
- [Kernel Pool Overflow Exploitation In Real World – Windows 7](http://trackwatch.com/kernel-pool-overflow-exploitation-in-real-world-windows-7/)
- [Kernel Pool Overflow Exploitation In Real World – Windows 10](http://trackwatch.com/kernel-pool-overflow-exploitation-in-real-world-windows-10/)
- [Many Formulas, One Calc – Exploiting a New Office Equation Vulnerability](https://research.checkpoint.com/another-office-equation-rce-vulnerability/)
- [Microsoft Kills Potential Remote Code Execution Vulnerability in Office (CVE-2017-8630)](https://securingtomorrow.mcafee.com/mcafee-labs/microsoft-kills-potential-remote-code-execution-vulnerability-in-office-cve-2017-8630/)
- [MS17-010: EternalBlue’s Large Non-Paged Pool Overflow in SRV Driver](http://blog.trendmicro.com/trendlabs-security-intelligence/ms17-010-eternalblue/)
- [MS OFFICE EXPLOIT ANALYSIS – CVE-2015-1641](http://www.sekoia.fr/blog/ms-office-exploit-analysis-cve-2015-1641/)
- [ON THE ROAD OF HIDING… PEB, PE FORMAT HANDLING AND DLL LOADING HOMEMADE APIS – PART 1](https://gbmaster.wordpress.com/2012/02/26/on-the-road-of-hiding-peb-pe-format-handling-and-dll-loading-homemade-apis-part-1/)
- [ON THE ROAD OF HIDING… PEB, PE FORMAT HANDLING AND DLL LOADING HOMEMADE APIS – PART 2](https://gbmaster.wordpress.com/2012/03/02/on-the-road-of-hiding-peb-pe-format-handling-and-dll-loading-homemade-apis-part-2/)
- [ON THE ROAD OF HIDING… PEB, PE FORMAT HANDLING AND DLL LOADING HOMEMADE APIS – PART 3](https://gbmaster.wordpress.com/2012/04/02/on-the-road-of-hiding-peb-pe-format-handling-and-dll-loading-homemade-apis-part-3/)
- [ON THE ROAD OF HIDING… PEB, PE FORMAT HANDLING AND DLL LOADING HOMEMADE APIS – LAST PART](https://gbmaster.wordpress.com/2012/04/17/on-the-road-of-hiding-peb-pe-format-handling-and-dll-loading-homemade-apis-last-part/)
- [Puppet Strings - Dirty Secret for Windows Ring 0 Code Execution](https://zerosum0x0.blogspot.com/2017/07/puppet-strings-dirty-secret-for-free.html?m=1)
- [Reading Your Way Around UAC (Part 1)](https://tyranidslair.blogspot.com/2017/05/reading-your-way-around-uac-part-1.html)
- [Reading Your Way Around UAC (Part 2)](https://tyranidslair.blogspot.com/2017/05/reading-your-way-around-uac-part-2.html)
- [Reading Your Way Around UAC (Part 3)](https://tyranidslair.blogspot.com/2017/05/reading-your-way-around-uac-part-3.html)
- [Reflective DLL Injection](https://0x00sec.org/t/reflective-dll-injection/3080)
- [Rotten Potato – Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)
- [sam-b/windows_kernel_resources](https://github.com/sam-b/windows_kernel_resources)
- [Sharks in the Pool :: Mixed Object Exploitation in the Windows Kernel Pool](http://srcincite.io/blog/2017/09/06/sharks-in-the-pool-mixed-object-exploitation-in-the-windows-kernel-pool.html)
- [Signing Mimikatz](https://twitter.com/subTee/status/912769644473098240)
- [Skeleton in the closet. MS Office vulnerability you didn’t know about](https://embedi.com/blog/skeleton-closet-ms-office-vulnerability-you-didnt-know-about/)
- [Starting with Windows Kernel Exploitation – part 1 – setting up the lab](https://hshrzd.wordpress.com/2017/05/28/starting-with-windows-kernel-exploitation-part-1-setting-up-the-lab/)
- [Starting with Windows Kernel Exploitation – part 2 – getting familiar with HackSys Extreme Vulnerable Driver](https://hshrzd.wordpress.com/2017/06/05/starting-with-windows-kernel-exploitation-part-2/)
- [Starting with Windows Kernel Exploitation – part 3 – stealing the Access Token](https://hshrzd.wordpress.com/2017/06/22/starting-with-windows-kernel-exploitation-part-3-stealing-the-access-token/)
- [Tales from the MSRC: from pixels to POC](https://blogs.technet.microsoft.com/srd/2017/06/20/tales-from-the-msrc-from-pixels-to-poc/)
- [The Art of Becoming TrustedInstaller](https://tyranidslair.blogspot.co.id/2017/08/the-art-of-becoming-trustedinstaller.html)
- [The lonely potato](https://decoder.cloud/2017/12/23/the-lonely-potato/)
- [The Unpatched LSASS Remote Denial of Service (MS16-137)](https://www.coresecurity.com/blog/unpatched-lsass-remote-denial-service-ms16-137)
- [Using Binary Diffing to Discover Windows Kernel Memory Disclosure Bugs](http://googleprojectzero.blogspot.com/2017/10/using-binary-diffing-to-discover.html)
- [Windows 10 Creators Update 32-bit execution of ring-0 code from NULL page via NtQuerySystemInformation (class 185, Warbird functionality)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1391)
- [Windows Exploitation Tricks: Arbitrary Directory Creation to Arbitrary File Read](https://googleprojectzero.blogspot.com/2017/08/windows-exploitation-tricks-arbitrary.html)
- [Windows kernel pool spraying fun - Part 1 - Determine kernel object size](http://theevilbit.blogspot.com/2017/09/pool-spraying-fun-part-1.html)
- [Windows kernel pool spraying fun - Part 2 - More objects](http://theevilbit.blogspot.com/2017/09/windows-kernel-pool-spraying-fun-part-2.html)
- [Windows kernel pool spraying fun - Part 3 - Let's make holes](http://theevilbit.blogspot.com/2017/09/windows-kernel-pool-spraying-fun-part-3.html)
- [Windows kernel pool spraying fun - Part 4 - object & pool headers, kex & putting it all together](http://theevilbit.blogspot.com/2017/09/windows-kernel-pool-spraying-fun-part-4.html)
- [Windows Kernel Exploitation Part 1](http://resources.infosecinstitute.com/windows-kernel-exploitation-part-1/)
- [Windows Kernel Exploitation Part 2](http://resources.infosecinstitute.com/kernel-exploitation-part-2/)
- [Windows Kernel Exploitation Part 3](http://resources.infosecinstitute.com/kernel-exploitation-part-3/)
- [Windows Kernel Exploitation Tutorial Part 1: Setting up the Environment](https://rootkits.xyz/blog/2017/06/kernel-setting-up/)
- [Windows Kernel Exploitation Tutorial Part 2: Stack Overflow](https://rootkits.xyz/blog/2017/08/kernel-stack-overflow/)
- [Windows Kernel Exploitation Tutorial Part 3: Arbitrary Memory Overwrite (Write-What-Where)](https://rootkits.xyz/blog/2017/09/kernel-write-what-where/)
- [Windows Kernel Exploitation Tutorial Part 4: Pool Feng-Shui –> Pool Overflow](https://rootkits.xyz/blog/2017/11/kernel-pool-overflow/)
- [Windows Kernel Exploitation Tutorial Part 5: NULL Pointer Dereference](https://rootkits.xyz/blog/2018/01/kernel-null-pointer-dereference/)
- [Windows Kernel Exploitation Tutorial Part 6: Uninitialized Stack Variable](https://rootkits.xyz/blog/2018/01/kernel-uninitialized-stack-variable/)
- [Windows Kernel Exploitation Tutorial Part 7: Uninitialized Heap Variable](https://rootkits.xyz/blog/2018/03/kernel-uninitialized-heap-variable/)
- [Windows Kernel Exploitation – Arbitrary Overwrite](https://osandamalith.com/2017/06/14/windows-kernel-exploitation-arbitrary-overwrite/)
- [Windows Kernel Exploitation : This Time Font hunt you down in 4 bytes](https://www.slideshare.net/PeterHlavaty/windows-kernel-exploitation-this-time-font-hunt-you-down-in-4-bytes)
- [Windows Operating System Archaeology](https://www.slideshare.net/enigma0x3/windows-operating-system-archaeology)
- [Zero Day Zen Garden: Windows Exploit Development - Part 0 [Dev Setup & Advice]](http://www.shogunlab.com/blog/2017/08/11/zdzg-windows-exploit-0.html)
- [Zero Day Zen Garden: Windows Exploit Development - Part 1 [Stack Buffer Overflow Intro]](http://www.shogunlab.com/blog/2017/08/19/zdzg-windows-exploit-1.html)
- [Zero Day Zen Garden: Windows Exploit Development - Part 2 [JMP to Locate Shellcode]](http://www.shogunlab.com/blog/2017/08/26/zdzg-windows-exploit-2.html)
- [Zero Day Zen Garden: Windows Exploit Development - Part 3 [Egghunter to Locate Shellcode]](http://www.shogunlab.com/blog/2017/09/02/zdzg-windows-exploit-3.html)

#### Technique: Bypassing ASLR

*Any related techniques for ASLR bypassing*

- [Bypass ASLR with partial EIP overwrite](http://ly0n.me/2015/07/30/bypass-aslr-with-partial-eip-overwrite/)
- [Bypassing ASLR – Part I](https://sploitfun.wordpress.com/2015/05/08/bypassing-aslr-part-i/)
- [Bypassing ASLR – Part II](https://sploitfun.wordpress.com/2015/05/08/bypassing-aslr-part-ii/)
- [Bypassing ASLR – Part III](https://sploitfun.wordpress.com/2015/05/08/bypassing-aslr-part-iii/)
- [Exploit Mitigation Techniques - Address Space Layout Randomization (ASLR)](https://0x00sec.org/t/exploit-mitigation-techniques-address-space-layout-randomization-aslr/5452/1)
- [New bypass and protection techniques for ASLR on Linux](http://blog.ptsecurity.com/2018/02/new-bypass-and-protection-techniques.html)

#### Technique: Format Strings

*Format strings exploitation*

- [Format String Exploitation Primer](https://borgandrew.blogspot.com/2017/01/h1-margin-bottom-0.html)
- [X86 EXPLOITATION 101: “FORMAT STRINGS” – I’LL TELL YA WHAT TO SAY](https://gbmaster.wordpress.com/2015/12/08/x86-exploitation-101-format-strings-ill-tell-ya-what-to-say/)

#### Technique: Heap Exploitation

*Heap exploitation related articles and tutorials*

- [Heap Exploitation](https://www.gitbook.com/book/dhavalkapil/heap-exploitation/details)
- [Heap Exploitation ~ Fastbin Attack](https://0x00sec.org/t/heap-exploitation-fastbin-attack/3627)
- [Heap Exploitation ~ Abusing Use-After-Free](https://0x00sec.org/t/heap-exploitation-abusing-use-after-free/3580)
- [Heap overflow using unlink](https://sploitfun.wordpress.com/2015/02/26/heap-overflow-using-unlink/)
- [Heap overflow using Malloc Maleficarum](https://sploitfun.wordpress.com/2015/03/04/heap-overflow-using-malloc-maleficarum/)
- [Heap Safari - Thread Local Caching](https://0x00sec.org/t/heap-safari-thread-local-caching/5054)
- [shellphishi/how2heap](https://github.com/shellphish/how2heap)
- [X86 EXPLOITATION 101: HEAP OVERFLOWS… UNLINK ME, WOULD YOU PLEASE?](https://gbmaster.wordpress.com/2014/08/11/x86-exploitation-101-heap-overflows-unlink-me-would-you-please/)
- [X86 EXPLOITATION 101: THIS IS THE FIRST WITCHY HOUSE](https://gbmaster.wordpress.com/2014/08/24/x86-exploitation-101-this-is-the-first-witchy-house/)
- [X86 EXPLOITATION 101: “HOUSE OF MIND” – UNDEAD AND LOVING IT…](https://gbmaster.wordpress.com/2015/06/15/x86-exploitation-101-house-of-mind-undead-and-loving-it/)
- [X86 EXPLOITATION 101: “HOUSE OF FORCE” – JEDI OVERFLOW](https://gbmaster.wordpress.com/2015/06/28/x86-exploitation-101-house-of-force-jedi-overflow/)
- [X86 EXPLOITATION 101: “HOUSE OF LORE” – PEOPLE AND TRADITIONS](https://gbmaster.wordpress.com/2015/07/16/x86-exploitation-101-house-of-lore-people-and-traditions/)
- [Understanding the Heap & Exploiting Heap Overflows](http://www.mathyvanhoef.com/2013/02/understanding-heap-exploiting-heap.html)

#### Technique: Integer Overflow

*Integer overflow exploitaion*

- [Integer Overflow](https://sploitfun.wordpress.com/2015/06/23/integer-overflow/)
- [X86 EXPLOITATION 101: “INTEGER OVERFLOW” – ADDING ONE MORE… AAAAAAAAAAAND IT’S GONE](https://gbmaster.wordpress.com/2015/08/13/x86-exploitation-101-integer-overflow-adding-one-more-aaaaaaaaaaand-its-gone/)

#### Technique: Return Oriented Programming

*ROP examples and guidelines*

- [A ROP Primer solution 64-bit style](https://blog.techorganic.com/2015/10/09/a-rop-primer-solution-64-bit-style/)
- [Blind Return Oriented Programming 102](https://oddcoder.com/BROP-102/)
- [Intro to ROP: ROP Emporium — Split](https://medium.com/@iseethieves/intro-to-rop-rop-emporium-split-9b2ec6d4db08)
- [Introduction to Return Oriented Programming (ROP)](https://ketansingh.net/Introduction-to-Return-Oriented-Programming-ROP/index.html)
- [Return-Oriented Programming (ROP) 101](https://www.tripwire.com/state-of-security/off-topic/vert-vuln-school-return-oriented-programming-rop-101/)
- [ROP Emporium](https://ropemporium.com/)
- [ROP Primer](https://speakerdeck.com/barrebas/rop-primer)
- [ropchain](http://www.kvakil.me/posts/ropchain/)
- [Sigreturn Oriented Programming](https://0x00sec.org/t/srop-signals-you-say/2890)

#### Technique: return-to-libc

*return-to-libc techniques*

- [Bypassing NX bit using return-to-libc](https://sploitfun.wordpress.com/2015/05/08/bypassing-nx-bit-using-return-to-libc/)
- [Bypassing NX bit using chained return-to-libc](https://sploitfun.wordpress.com/2015/05/08/bypassing-nx-bit-using-chained-return-to-libc/)

#### Technique: Shellcoding

*Art of crafting shellcode*

- [SLAE: Bind TCP Shell – Assignment 1](http://0xdeadcode.se/archives/637)
- [SLAE: Reverse TCP Shell – Assignment 2](http://0xdeadcode.se/archives/689)
- [SLAE: Egg Hunter – Assignment 3](http://0xdeadcode.se/archives/707)

#### Technique: Stack Exploitation

*Corrupt the stack*

- [Buffer Overflow Explotation](https://0x00sec.org/t/buffer-overflow-explotation/3846/1)
- [Classic Stack Based Buffer Overflow](https://sploitfun.wordpress.com/2015/05/08/classic-stack-based-buffer-overflow/)
- [Exploiting 1-byte buffer overflows](https://www.welivesecurity.com/2016/05/10/exploiting-1-byte-buffer-overflows/)
- [PLAYING WITH CANARIES](https://www.elttam.com.au/blog/playing-with-canaries/)
- [Simple buffer overflow on a modern system](http://liveoverflow.com/blog/stack0_buffer_overflow_on_ubuntu.html)
- [Stack Based Buffer Overflows on x64 (Windows)](Stack Based Buffer Overflows on x64 (Windows))
- [Stack Clashing for Fun and Profit](http://nullprogram.com/blog/2017/06/21/)
- [When is something overflowing](https://www.slideshare.net/PeterHlavaty/overflow-48573748)
- [X86 EXPLOITATION 101: WHEN THE STACK GETS OVER ITS HEAD](https://gbmaster.wordpress.com/2014/06/18/x86-exploitation-101-when-the-stack-gets-over-its-head/)
- [X86 EXPLOITATION 101: BORN IN A SHELL](https://gbmaster.wordpress.com/2014/07/01/x86-exploitation-101-born-in-a-shell/)
- [X86 EXPLOITATION 101: “HOUSE OF SPIRIT” – FRIENDLY STACK OVERFLOW](https://gbmaster.wordpress.com/2015/07/21/x86-exploitation-101-house-of-spirit-friendly-stack-overflow/)
- [Your First Buffer Overflow](https://medium.com/@mackwage/your-first-buffer-overflow-89141a9a2941)

#### Technique Use-After-Free

*Use-After-Free related arcitles*

![https://twitter.com/bellis1000/status/930154591081070592](https://pbs.twimg.com/media/DOiSqmWX0AEVeya.jpg)

- [Use-After-Free](https://sploitfun.wordpress.com/2015/06/16/use-after-free/)

#### Vulnerability: Spectre and Meltdown

- [A Deep Dive Analysis of Microsoft’s Kernel Virtual Address Shadow Feature](A Deep Dive Analysis of Microsoft’s Kernel Virtual Address Shadow Feature)
- [An accessible overview of Meltdown and Spectre, Part 1](https://blog.trailofbits.com/2018/01/30/an-accessible-overview-of-meltdown-and-spectre-part-1/)
- [An accessible overview of Meltdown and Spectre, Part 2](https://blog.trailofbits.com/2018/03/22/an-accessible-overview-of-meltdown-and-spectre-part-2/)
- [KVA Shadow: Mitigating Meltdown on Windows](https://blogs.technet.microsoft.com/srd/2018/03/23/kva-shadow-mitigating-meltdown-on-windows/)
- [Total Meltdown?](https://blog.frizk.net/2018/03/total-meltdown.html)

### Malware Analysis

- [A zebra in sheep’s clothing: How a Microsoft icon-display bug in Windows allows attackers to masquerade PE files with special icons](https://www.cybereason.com/labs-a-zebra-in-sheeps-clothing-how-a-microsoft-icon-display-bug-in-windows-allows-attackers-to-masquerade-pe-files-with-special-icons/)
- [baderj/domain_generation_algorithms - Some results of my DGA reversing efforts](https://github.com/baderj/domain_generation_algorithms)
- [DOSfuscation: Exploring the Depths Cmd.exe Obfuscation and Detection Techniques](https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/dosfuscation-report.pdf)
- [Fast Flux networks: What are they and how do they work?](https://www.welivesecurity.com/2017/01/12/fast-flux-networks-work/)
- [FIN7 Group Uses JavaScript and Stealer DLL Variant in New Attacks](http://blog.talosintelligence.com/2017/09/fin7-stealer.html#more)
- [High-reputation Redirectors and Domain Fronting](https://blog.cobaltstrike.com/2017/02/06/high-reputation-redirectors-and-domain-fronting/)
- [Hunting For In-Memory .NET Attacks](https://www.endgame.com/blog/technical-blog/hunting-memory-net-attacks)
- [Hunting Malware with Memory Analysis](https://technical.nttsecurity.com/post/102egyy/hunting-malware-with-memory-analysis)
- [Reverse Engineering Malware](https://www.hackers-arise.com/reverse-engineering-malware)
- [Reverse Engineering Malware: Why YOU Should Study Reverse Engineering Malware](https://www.hackers-arise.com/single-post/2017/01/18/Reverse-Engineering-Malware-Why-YOU-Should-Study-Reverse-Engineering-Malware)
- [Reverse Engineering Malware, Part 1: Getting Started](https://www.hackers-arise.com/single-post/2017/02/17/Reverse-Engineering-Malware-Part-1-Getting-Started)
- [Reverse Engineering Malware, Part 2: Assembler Language Basics](https://www.hackers-arise.com/single-post/2017/02/27/Reverse-Engineering-Malware-Part-2-Assembler-Language-Basics)
- [Reverse Engineering Malware, Part 3: IDA Pro Introduction](https://www.hackers-arise.com/single-post/2017/06/22/Reverse-Engineering-Malware-Part-3-IDA-Pro-Introduction)
- [Reverse Engineering Malware, Part 4: Windows Internals](https://www.hackers-arise.com/single-post/2017/07/04/Reverse-Engineering-Malware-Part-4-Windows-Internals)
- [Reverse Engineering Malware, Part 5: OllyDbg Basics](https://www.hackers-arise.com/single-post/2017/10/03/Reverse-Engineering-Malware-Part-5-OllyDbg-Basics)
- [ThreatHuntingProject/ThreatHunting](https://github.com/ThreatHuntingProject/ThreatHunting)
- [Tips for Reverse-Engineering Malicious Code](https://zeltser.com/reverse-engineering-malicious-code-tips/)
- [Understanding Process Hollowing](https://andreafortuna.org/understanding-process-hollowing-b94ce77c3276)
- [Use of DNS Tunneling for C&C Communications](https://securelist.com/use-of-dns-tunneling-for-cc-communications/78203/)
- [Add-In Opportunities for Office Persistence](https://labs.mwrinfosecurity.com/blog/add-in-opportunities-for-office-persistence/)
- [Anti-debugging Techniques Cheat Sheet](http://antukh.com/blog/2015/01/19/malware-techniques-cheat-sheet/)
- [AntiForensics techniques : Process hiding in Kernel Mode](https://www.cert-devoteam.fr/publications/en/antiforensics-techniques-process-hiding-in-kernel-mode/)
- [Borrowing Microsoft Code Signing Certificate](https://blog.conscioushacker.io/index.php/2017/09/27/borrowing-microsoft-code-signing-certificates/)
- [Creating ransomware for Android](https://0x00sec.org/t/creating-ransomware-for-android/4063)
- [Detecting Architecture in Windows](https://osandamalith.com/2017/09/24/detecting-architecture-in-windows/)
- [HIDING YOUR PROCESS FROM SYSINTERNALS](https://riscybusiness.wordpress.com/2017/10/07/hiding-your-process-from-sysinternals/)
- [If memory doesn’t serve me right…](http://www.hexacorn.com/blog/2017/07/10/if-memory-doesnt-serve-me-right/)
- [MetaTwin – Borrowing Microsoft Metadata and Digital Signatures to “Hide” Binaries](http://threatexpress.com/2017/10/metatwin-borrowing-microsoft-metadata-and-digital-signatures-to-hide-binaries/)
- [PE File Infection Part I](https://0x00sec.org/t/pe-file-infection/401)
- [PE File Infection Part II](https://0x00sec.org/t/pe-file-infection-part-ii/4135)
- [Running programs via Proxy & jumping on a EDR-bypass trampoline](http://www.hexacorn.com/blog/2017/05/01/running-programs-via-proxy-jumping-on-a-edr-bypass-trampoline/)
- [Running programs via Proxy & jumping on a EDR-bypass trampoline, Part 2](http://www.hexacorn.com/blog/2017/10/04/running-programs-via-proxy-jumping-on-a-edr-bypass-trampoline-part-2/)
- [Running programs via Proxy & jumping on a EDR-bypass trampoline, Part 3](http://www.hexacorn.com/blog/2017/10/22/running-programs-via-proxy-jumping-on-a-edr-bypass-trampoline-part-3/)
- [Running programs via Proxy & jumping on a EDR-bypass trampoline, Part 4](http://www.hexacorn.com/blog/2017/10/29/running-programs-via-proxy-jumping-on-a-edr-bypass-trampoline-part-4/)
- [Ten Process Injection Techniques: A Technical Survey Of Common And Trending Process Injection Techniques](https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process)
- [The Archaeologologogology #3 – Downloading stuff with cmdln32](http://www.hexacorn.com/blog/2017/04/30/the-archaeologologogology-3-downloading-stuff-with-cmdln32/)
- ATM malware
    - [Bingo, Amigo! Jackpotting: ATM malware from Latin America to the World](https://securelist.com/atm-malware-from-latin-america-to-the-world/83836/)
- Badrabbit
    - [‘BadRabbit’ Ransomware Burrows Into Russia, Ukraine](https://securingtomorrow.mcafee.com/mcafee-labs/badrabbit-ransomware-burrows-russia-ukraine/)
    - [BadRabbit: a closer look at the new version of Petya/NotPetya](https://blog.malwarebytes.com/threat-analysis/2017/10/badrabbit-closer-look-new-version-petyanotpetya/)
    - [Bad Rabbit: Not-Petya is back with improved ransomware](https://www.welivesecurity.com/2017/10/24/bad-rabbit-not-petya-back/)
    - [Bad Rabbit – A New Ransomware Outbreak Targeting Ukraine and Russia.](https://blog.checkpoint.com/2017/10/24/bad-rabbit-new-ransomware-outbreak-targeting-ukraine-russia/)
    - [Bad Rabbit ransomware](https://securelist.com/bad-rabbit-ransomware/82851/)
    - [Bad Rabbit Ransomware Spreads via Network, Hits Ukraine and Russia](http://blog.trendmicro.com/trendlabs-security-intelligence/bad-rabbit-ransomware-spreads-via-network-hits-ukraine-russia/)
    - [NotPetya Returns as Bad Rabbit](http://www.intezer.com/notpetya-returns-bad-rabbit/)
    - [Threat Spotlight: Follow the Bad Rabbit](http://blog.talosintelligence.com/2017/10/bad-rabbit.html)
- Bankbot
    - [A Look Into The New Strain of BankBot](https://blog.fortinet.com/2017/09/19/a-look-into-the-new-strain-of-bankbot)
- CCleaner
   - [Protecting the Software Supply Chain: Deep Insights into the CCleaner Backdoor](https://www.crowdstrike.com/blog/protecting-software-supply-chain-deep-insights-ccleaner-backdoor/)
    - [In-Depth Analysis of the CCleaner Backdoor Stage 2 Dropper and Its Payload](https://www.crowdstrike.com/blog/in-depth-analysis-of-the-ccleaner-backdoor-stage-2-dropper-and-its-payload/)
- Dridex
    - [Dridex v4 - Configuration Files, Network and Binaries](https://viql.github.io/dridex/)
- Emotet
    - [Emotet lives another day using Fake O2 invoice notifications](https://www.trustwave.com/Resources/SpiderLabs-Blog/Emotet-lives-another-day-using-Fake-O2-invoice-notifications/)
- Hajime
    - [Is Hajime botnet dead?](http://blog.netlab.360.com/hajime-status-report-en/)
- Locky
    - [Locky Part 1: Lukitus Spam Campaigns and Their Love for Game of Thrones](https://www.trustwave.com/Resources/SpiderLabs-Blog/Locky-Part-1--Lukitus-Spam-Campaigns-and-Their-Love-for-Game-of-Thrones/)
    - [Locky Part 2: As the Seasons Change so is Locky](https://www.trustwave.com/Resources/SpiderLabs-Blog/Locky-Part-2--As-the-Seasons-Change-so-is-Locky/)
- Kangaroo
    - [Threat Analysis: Don’t Forget About Kangaroo Ransomware](https://www.carbonblack.com/2017/10/02/threat-analysis-dont-forget-about-kangaroo-ransomware/)
- MAN1
    - [Threat Spotlight - MAN1 Malware: Temple of Doom](https://www.cylance.com/en_us/blog/threat-spotlight-man1-malware-group-resurfaces.html)
    - [Threat Spotlight: MAN1 Malware - The Last Crusade?](https://www.cylance.com/en_us/blog/threat-spotlight-man1-malware-the-last-crusade.html)
- Poison Ivy
    - [Deep Analysis of New Poison Ivy Variant](http://blog.fortinet.com/2017/08/23/deep-analysis-of-new-poison-ivy-variant)
    - [Deep Analysis of New Poison Ivy/PlugX Variant - Part II](https://blog.fortinet.com/2017/09/15/deep-analysis-of-new-poison-ivy-plugx-variant-part-ii)
- Rig EK
    - [if you want to get #RigEK's enc key, please use this script](https://twitter.com/nao_sec/status/944038611590115328)
- Trickbot
    - [Reverse engineering malware: TrickBot (part 1 - packer)](https://qmemcpy.github.io/post/reverse-engineering-malware-trickbot-part-1-packer)
    - [Reverse engineering malware: TrickBot (part 2 - loader)](https://qmemcpy.github.io/post/reverse-engineering-malware-trickbot-part-2-loader)
    - [Reverse engineering malware: TrickBot (part 3 - core)](https://qmemcpy.io/post/reverse-engineering-malware-trickbot-part-3-core)

### Mobile Security

- [tanprathan/MobileApp-Pentest-Cheatsheet](https://github.com/tanprathan/MobileApp-Pentest-Cheatsheet)

### Post Exploitation

#### Windows Post Exploitation

- [Top Five Ways I Got Domain Admin on Your Internal Network before Lunch (2018 Edition)](https://medium.com/@adam.toscher/top-five-ways-i-got-domain-admin-on-your-internal-network-before-lunch-2018-edition-82259ab73aaa)

### Reverse Engineering

- [A Gentle Primer on Reverse Engineering](https://emily.st/2015/01/27/reverse-engineering/)
- [ELF hacking with Rekall](http://blog.rekall-forensic.com/2018/01/elf-hacking-with-rekall.html)
- [FAQ: How to learn reverse-engineering?](http://gynvael.coldwind.pl/?id=664)
- [How to decompile any Python binary](https://countercept.com/our-thinking/how-to-decompile-any-python-binary/)
- [Reverse Engineering 101](https://osandamalith.com/2014/12/31/reverse-engineering-101/)

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
                <li><a href="https://tunnelshade.in/blog/2018/01/afl-internals-compile-time-instrumentation/">Internals of AFL fuzzer - Compile Time Instrumentation</a></li>
            </ul>
        </td>
    </tr>
    <tr>
        <td>Amazon Web Services (AWS)</td>
        <td>
            <ul>
                <li><a href="https://github.com/open-guides/og-aws">open-guides/og-aws</a></li>
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
        <td>Mimikatz</td>
        <td>
            <ul>
                <li><a href="https://adsecurity.org/?page_id=1821">Unofficial Guide to Mimikatz & Command Reference</a></li>
            </ul>
        </td>
    </tr>
    <tr>
        <td>MISP</td>
        <td>
            <ul>
                <li><a href="https://github.com/remg427/misp42splunk/">remg427/misp42splunk</a></li>
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
                <li><a href="https://blogs.technet.microsoft.com/motiba/2017/12/07/sysinternals-sysmon-suspicious-activity-guide/">Sysinternals Sysmon suspicious activity guide</a></li>
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
                <li><a href="https://leotindall.com/tutorial/an-intro-to-x86_64-reverse-engineering/">An Intro to x86_64 Reverse Engineering</a></li>
                <li><a href="http://blog.superponible.com/2017/04/15/emulating-assembly-in-radare2/">Emulating Assembly in Radare2</a></li>
                <li><a href="https://github.com/chrysh/ctf_writeups/tree/master/pwnable.kr">Pwnable.kr - Passcode</a></li>
                <li><a href="https://radare2.securisec.com/">r2wiki</a></li>
                <li><a href="https://monosource.github.io/2016/10/radare2-peda">radare2 as an alternative to gdb-peda</a></li>
                <li><a href="https://medium.com/@jacob16682/reverse-engineering-using-radare2-588775ea38d5">Reverse Engineering Using Radare2</a></li>
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

## Web Application Security

*Web application security related articles and tutorials*

- [Gaining access for HTTPS certificate by abusing RFC2142.](https://twitter.com/spazef0rze/status/942800411941048320)
    - Using `admin@`, `administrator@`, `hostmaster@`, `postmaster@`, `webmaster@` for email address
- [The 2018 Guide to Building Secure PHP Software](https://paragonie.com/blog/2017/12/2018-guide-building-secure-php-software)

### Cross-site Request Forgery

- [What is CSRF , Preventions? And How to bypass the CSRF protection via XSS?](https://medium.com/@agrawalsmart7/what-is-csrf-how-to-bypass-the-csrf-protection-via-xss-55695f5789d7)

### Cross-site Scripting

- [BRUTE XSS - Master the art of Cross Site Scripting](https://brutelogic.com.br/blog/)
- [XSS Cheat Sheet](https://leanpub.com/xss)

### SQL Injection

- [MySQL UDF Exploitation](https://osandamalith.com/2018/02/11/mysql-udf-exploitation/)
- [NetSPI SQL Injection Wiki](https://sqlwiki.netspi.com/)
- [Your Pokemon Guide for Essential SQL Pen Test Commands](https://pen-testing.sans.org/blog/2017/12/09/your-pokemon-guide-for-essential-sql-pen-test-commands)

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
    <tr>
        <td><a href="https://github.com/SecurityFTW/cs-suite">SecurityFTW/cs-suite</a></td>
        <td>Cloud Security Suite - One stop tool for auditing the security posture of AWS infrastructure.</td>
    </tr>
</table>

### Binary Analysis

*Binary analysis tools, including decompilers, deobfuscators, disassemblers, etc.*

<table>
    <tr>
        <td><a href="https://github.com/avast-tl/retdec">avast-tl/retdec</a></td>
        <td>RetDec is a retargetable machine-code decompiler based on LLVM</td>
    </tr>
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
        <td><a href="https://github.com/hasherezade/hook_finder">hasherezade/hook_finder</a></td>
        <td>a small tool for investigating inline hooks (and other in-memory code patches)</td>
    </tr>
    <tr>
        <td><a href="https://lief.quarkslab.com/">LIEF</a></td>
        <td>Library to Instrument Executable Formats</td>
    </tr>
    <tr>
        <td><a href="https://github.com/pierrezurek/Signsrch">pierrezurek/Signsrch</a></td>
        <td>tool for searching signatures inside files, extremely useful in reversing engineering for figuring or having an initial idea of what encryption/compression algorithm is used for a proprietary protocol or file. it can recognize tons of compression, multimedia and encryption algorithms and many other things like known strings and anti-debugging code which can be also manually added since it's all based on a text signature file read at runtime and easy to modify.</td>
    </tr>
    <tr>
        <td><a href="https://salmanarif.bitbucket.io/visual/index.html">VisUAL</a></td>
        <td>A highly visual ARM emulator</td>
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

### Cryptography

*Cryptography related tools*

<table>
    <tr>
        <td><a href="https://certdb.com">CertDB</a></td>
        <td>Internet-wide search engine for digital certificates</td>
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
        <td><a href="https://www.flashbackdata.com/free-forensics-tool-i-file-parser/">$I File Parser</a></td>
        <td>Free Forensics Tool – $I File Parser</td>
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
        <td><a href="https://github.com/Cyb3rWard0g/HELK">Cyb3rWard0g/HELK</a></td>
        <td>A Hunting ELK (Elasticsearch, Logstash, Kibana) with advanced analytic capabilities.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ForensicArtifacts/artifacts">ForensicArtifacts/artifacts</a></td>
        <td>Digital Forensics Artifact Repository</td>
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
        <td><a href="https://arsenalrecon.com/weapons/hibernation-recon/">Hibernation Recon</a></td>
        <td>The tools and techniques used for many years to analyze Microsoft Windows® hibernation files have left digital forensics experts in the dark… until now!</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Invoke-IR/ACE">Invoke-IR/ACE</a></td>
        <td>The Automated Collection and Enrichment (ACE) platform is a suite of tools for threat hunters to collect data from many endpoints in a network and automatically enrich the data. The data is collected by running scripts on each computer without installing any software on the target. ACE supports collecting from Windows, macOS, and Linux hosts.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/JPCERTCC/LogonTracer">JPCERTCC/LogonTracer</a></td>
        <td>Investigate malicious Windows logon by visualizing and analyzing Windows event log</td>
    </tr>
    <tr>
        <td><a href="https://github.com/intezer/linux-explorer">intezer/linux-explorer</a></td>
        <td>Easy-to-use live forensics toolbox for Linux endpoints</td>
    </tr>
    <tr>
        <td><a href="https://technet.microsoft.com/en-us/scriptcenter/dd919274.aspx">Log Parser</a></td>
        <td>Log Parser 2.2 is a powerful, versatile tool that provides universal query access to text-based data such as log files, XML files and CSV files, as well as key data sources on the Windows operating system such as the Event Log, the Registry, the file system, and Active Directory</td>
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
        <td><a href="https://github.com/williballenthin/INDXParse">williballenthin/INDXParse</a></td>
        <td>Tool suite for inspecting NTFS artifacts</td>
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
        <td><a href="https://github.com/refractionPOINT/limacharlie">refractionPOINT/limacharlie</a></td>
        <td>LC is an Open Source, cross-platform (Windows, MacOS, Linux ++), realtime Endpoint Detection and Response sensor. The extra-light sensor, once installed on a system provides Flight Data Recorder type information (telemetry on all aspects of the system like processes, DNS, network IO, file IO etc).</td>
    </tr>
    <tr>
        <td><a href="https://www.sleuthkit.org/">The Sleuth Kit</a></td>
        <td>sleuthkit.org is the official website for The Sleuth Kit®, Autopsy®, and other open source digital investigation tools. From here, you can find documents, case studies, and download the latest versions of the software.</td>
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
    <tr>
        <td><a href="http://www.kazamiya.net/en/usn_analytics">USN Analytics</a></td>
        <td>USN Analytics is a tool that specializes in USN Journal ($UsnJrnl:$J) analysis</td>
    </tr>
    <tr>
        <td><a href="https://github.com/williballenthin/EVTXtract">williballenthin/EVTXtract</a></td>
        <td>EVTXtract recovers and reconstructs fragments of EVTX log files from raw binary data, including unallocated space and memory images.</td>
    </tr>
</table>

### Exploits

*Interesting exploits and PoC code. For research purpose only*

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
        <td>CVE-2017-5753, CVE-2017-5715, CVE-2017-5754</td>
        <td>
            Meltdown and Spectre exploit critical vulnerabilities in modern processors. These hardware bugs allow programs to steal data which is currently processed on the computer. While programs are typically not permitted to read data from other programs, a malicious program can exploit Meltdown and Spectre to get hold of secrets stored in the memory of other running programs. This might include your passwords stored in a password manager or browser, your personal photos, emails, instant messages and even business-critical documents.
            <ul>
                <li><a href="https://twitter.com/gsuberland/status/948907452786933762">Explanation threat by @gsuverland</a></li>
                <li><a href="https://github.com/Eugnis/spectre-attack">Eugnis/spectre-attack</a></li>
                <li><a href="https://github.com/IAIK/meltdown">IAIK/meltdown</a></li>
                <li><a href="https://github.com/lgeek/spec_poc_arm">lgeek/spec_poc_arm</a></li>
                <li><a href="https://github.com/paboldin/meltdown-exploit">paboldin/meltdown-exploit</a></li>
                <li><a href="https://spectreattack.com/">Meltdown and Spectre</a></li>
                <li><a href="https://googleprojectzero.blogspot.com/2018/01/reading-privileged-memory-with-side.html">Reading privileged memory with a side-channel</a></li>
                <li><a href="http://www.kb.cert.org/vuls/id/584653">CPU hardware vulnerable to side-channel attacks</a></li>
                <li><a href="https://github.com/ionescu007/SpecuCheck">ionescu007/SpecuCheck</a></li>
                <li><a href="https://github.com/raphaelsc/Am-I-affected-by-Meltdown">raphaelsc/Am-I-affected-by-Meltdown</a></li>
                <li><a href="https://twitter.com/x0rz/status/948832798391066624">Detection tool (2)</a></li>
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
        <td>CVE-2017-8750</td>
        <td>Microsoft Office allows a remote code execution vulnerability due to the way that it handles objects in memory, aka "Microsoft Office Remote Code Execution Vulnerability". This CVE ID is unique from CVE-2017-0243.
            <ul>
                <li><a href="https://github.com/rxwx/CVE-2017-8570">Proof of Concept exploit for CVE-2017-8570</a></li>
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
        <td>CVE-2017-15944</td>
        <td>Palo Alto Networks PAN-OS before 6.1.19, 7.0.x before 7.0.19, 7.1.x before 7.1.14, and 8.0.x before 8.0.6 allows remote attackers to execute arbitrary code via vectors involving the management interface.
            <ul>
                <li><a href="http://seclists.org/fulldisclosure/2017/Dec/38">CVE-2017-15944: Palo Alto Networks firewalls remote root code execution</a></li>
                <li><a href="http://seclists.org/fulldisclosure/2017/Dec/65">Exploit verification script</a></li>
            </ul>
        </td>
    </tr>
    <tr>
        <td>CVE-2017-16995</td>
        <td>The check_alu_op function in kernel/bpf/verifier.c in the Linux kernel through 4.14.8 allows local users to cause a denial of service (memory corruption) or possibly have unspecified other impact by leveraging incorrect sign extension.
            <ul>
                <li><a href="https://www.exploit-db.com/exploits/44298/">Linux Kernel < 4.4.0-116 (Ubuntu 16.04.4) - Local Privilege Escalation</a></li>
            </ul>
        </td>
    </tr>
    </tr>
        <td>CVE-2017-17215</td>
        <td>
            <ul>
                <li><a href="https://www.exploit-db.com/exploits/43414/">Huawei Router HG532 - Arbitrary Command Execution</a></li>
            </ul>
        </td>
    </tr>
    <tr>
        <td>CVE-2018-0743</td>
        <td>Windows Subsystem for Linux in Windows 10 version 1703, Windows 10 version 1709, and Windows Server, version 1709 allows an elevation of privilege vulnerability due to the way objects are handled in memory, aka "Windows Subsystem for Linux Elevation of Privilege Vulnerability".
            <ul>
                <li><a href="https://github.com/saaramar/execve_exploit">saaramar/execve_exploit</a></li>
            </ul>
        </td>
    </tr>
    <tr>
        <td>CVE-2018-4878</td>
        <td>A critical vulnerability (CVE-2018-4878) exists in Adobe Flash Player 28.0.0.137 and earlier versions. Successful exploitation could potentially allow an attacker to take control of the affected system.
            <ul>
                <li><a href="https://www.hybrid-analysis.com/sample/14c58e3894258c54e12d52d0fba0aafa258222ce9223a1fdc8a946fd169d8a12?environmentId=120">Malicious 0-day XLSX sample</a></li>
            </ul>
        </td>
    </tr>
    <tr>
        <td><a href="https://github.com/Eplox/TCP-Starvation">Eplox/TCP-Starvation</a></td>
        <td>The idea behind this attack is to close a TCP session on the attacker's side, while leaving it open for the victim. Looping this will quickly fill up the victim’s session limit, effectively denying other users to access the service.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/FriendsOfPHP/security-advisories">FriendsOfPHP/security-advisories</a></td>
        <td>The PHP Security Advisories Database references known security vulnerabilities in various PHP projects and libraries. This database must not serve as the primary source of information for security issues, it is not authoritative for any referenced software, but it allows to centralize information for convenience and easy consumption.</td>
    </tr>
    <tr>
        <td><a href="hasherezade/process_doppelganging">https://github.com/hasherezade/process_doppelganging</a></td>
        <td>My implementation of enSilo's Process Doppelganging (PE injection technique)</td>
    </tr>
    <tr>
        <td><a href="https://github.com/gellin/TeamViewer_Permissions_Hook_V1"></a>gellin/TeamViewer_Permissions_Hook_V1</td>
        <td>A proof of concept injectable C++ dll, that uses naked inline hooking and direct memory modification to change your TeamViewer permissions.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/ScottyBauer/Android_Kernel_CVE_POCs">ScottyBauer/Android_Kernel_CVE_POCs</a></td>
        <td>A list of my CVE's with POCs</td>
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
        <td><a href="https://cape.contextis.com/submit/">CAPE Sandbox</a></td>
        <td>Malware Configuration And Payload Extraction</td>
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
        <td><a href="https://github.com/glmcdona/Process-Dump">glmcdona/Process-Dump</a></td>
        <td>Windows tool for dumping malware PE files from memory back to disk for analysis.</td>
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
        <td><a href="https://github.com/hegusung/AVSignSeek">hegusung/AVSignSeek</a></td>
        <td>Tool written in python3 to determine where the AV signature is located in a binary/payload</td>
    </tr>
    <tr>
        <td><a href="https://iris-h.malwageddon.com/">IRIS-H</a></td>
        <td>IRIS-H is an online digital forensics tool that performs automated static analysis of files stored in a directory-based or strictly structured formats.</td>
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
        <td><a href="https://github.com/LordNoteworthy/al-khaser">LordNoteworthy/al-khaser</a></td>
        <td>Public malware techniques used in the wild: Virtual Machine, Emulation, Debuggers, Sandbox detection.</td>
    </tr>
    <tr>
        <td><a href="https://malpedia.caad.fkie.fraunhofer.de/">Malpedia</a></td>
        <td>The primary goal of Malpedia is to provide a resource for rapid identification and actionable context when investigating malware. Openness to curated contributions shall ensure an accountable level of quality in order to foster meaningful and reproducible research.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/malwareinfosec/EKFiddle">malwareinfosec/EKFiddle</a></td>
        <td>A framework based on the Fiddler web debugger to study Exploit Kits, malvertising and malicious traffic in general.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Neo23x0/APTSimulator">Neo23x0/APTSimulator</a></td>
        <td>A toolset to make a system look as if it was the victim of an APT attack</td>
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
        <td><a href="https://github.com/OALabs/PyIATRebuild">OALabs/PyIATRebuild</a></td>
        <td>Automatically rebuild Import Address Table for dumped PE file. With python bindings!</td>
    </tr>
    <tr>
        <td><a href="https://github.com/phage-nz/ph0neutria">phage-nz/ph0neutria</a></td>
        <td>ph0neutria is a malware zoo builder that sources samples straight from the wild. Everything is stored in Viper for ease of access and manageability.</td>
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
    <tr>
        <td><a href="https://pan-unit42.github.io/playbook_viewer/">UNIT 42: Playbook Viewver</a></td>
        <td>Viewing PAN Unit 42's adversary playbook via web interface</td>
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
        <td><a href="https://github.com/linkedin/qark">linkedin/qark</a></td>
        <td>Tool to look for several security related Android application vulnerabilities</td>
    </tr>
    <tr>
        <td><a href="https://www.htbridge.com/mobile">Mobile X-Ray</a></td>
        <td>Just upload your iOS or Android mobile app to start a DAST, SAST and behavioral audit for OWASP Mobile Top 10 and other vulnerabilities</td>
    </tr>
    <tr>
        <td><a href="https://github.com/MobSF/Mobile-Security-Framework-MobSF">MobSF/Mobile-Security-Framework-MobSF</a></td>
        <td>Mobile Security Framework is an automated, all-in-one mobile application (Android/iOS/Windows) pen-testing framework capable of performing static analysis, dynamic analysis, malware analysis and web API testing</td>
    </tr>
</table>

### Network

*Network and network security related tools*

<table>
    <tr>
        <td><a href="https://github.com/eldraco/domain_analyzer/">eldraco/domain_analyzer</a></td>
        <td>Analyze the security of any domain by finding all the information possible. Made in python.</td>
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
        <td><a href="https://wireedit.com/">WireEdit</a></td>
        <td>First-Of-A-Kind And The Only Full Stack WYSIWYG Pcap Editor</td>
    </tr>
</table>

### Password Tools

*Tools related to password cracking, bruteforcing and also wordlists*

<table>
    <tr>
        <td><a href="https://github.com/berzerk0/Probable-Wordlists">berzerk0/Probable-Wordlists</a></td>
        <td>Wordlists sorted by probability originally created for password generation and testing - make sure your passwords aren't popular!</td>
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
        <td colspan="2"><b>Frida</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/brompwnie/uitkyk">brompwnie/uitkyk</a></td>
        <td>Uitkyk is a custom Android Frida libary which provides an API to analyze Android applications for malicious activity. This is a PoC library to illustrate the capabilities of performing runtime analysis on Android. Additionally Uitkyk is a collection of resources to assist in the identification of malicious Android applications at runtime.</td>
    </tr>
    <tr>
        <td colspan="2"><b>IDA Pro</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/airbus-seclab/bincat">airbus-seclab/bincat</a></td>
        <td>Binary code static analyser, with IDA integration. Performs value and taint analysis, type reconstruction.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/CrowdStrike/CrowdDetox">CrowdStrike/CrowdDetox</a></td>
        <td>The CrowdDetox plugin for Hex-Rays automatically removes junk code and variables from Hex-Rays function decompilations.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/fireeye/SimplifyGraph">fireeye/SimplifyGraph</a></td>
        <td>IDA Pro plugin to assist with complex graphs</td>
    </tr>
    <tr>
        <td><a href="https://github.com/IDAConnect/IDAConnect">IDAConnect/IDAConnect</a></td>
        <td>[WIP] Collaborative Reverse Engineering plugin for IDA Pro & Hex-Rays</td>
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
        <td><a href="https://github.com/joxeankoret/diaphora">joxeankoret/diaphora</a></td>
        <td>Diaphora, a Free and Open Source program diffing tool</td>
    </tr>
    <tr>
        <td><a href="https://github.com/OALabs/FindYara">OALabs/FindYara</a></td>
        <td>IDA python plugin to scan binary with Yara rules</td>
    </tr>
    <tr>
        <td><a href="https://github.com/onethawt/idaplugins-list">onethawt/idaplugins-list</a></td>
        <td>A list of IDA Plugins</td>
    </tr>
    <tr>
        <td><a href="https://github.com/tintinweb/ida-batch_decompile">tintinweb/ida-batch_decompile</a></td>
        <td>*Decompile All the Things* - IDA Batch Decompile plugin and script for Hex-Ray's IDA Pro that adds the ability to batch decompile multiple files and their imports with additional annotations (xref, stack var size) to the pseudocode .c file</td>
    </tr>
    <tr>
        <td><a href="https://github.com/Riscure/DROP-IDA-plugin">Riscure/DROP-IDA-plugin</a></td>
        <td>Experimental opaque predicate detection for IDA Pro</td>
    </tr>
    <tr>
        <td colspan="2"><b>Radare2</b></td>
    </tr>
    <tr>
        <td><a href="https://github.com/radareorg/cutter">radareorg/cutter</a></td>
        <td>A Qt and C++ GUI for radare2 reverse engineering framework</td>
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

### Privacy

*Increase your privacy and/or operational security with this tools*

<table>
    <tr>
        <td><a href="https://github.com/agherzan/yubikey-full-disk-encryption">agherzan/yubikey-full-disk-encryption</a></td>
        <td>Use YubiKey to unlock a LUKS partition</td>
    </tr>
    <tr>
        <td><a href="https://www.getoutline.org/en/home">Outline</a></td>
        <td>Making it safer to break the news</td>
    </tr>
    <tr>
        <td><a href="https://securityplanner.org/">Security Planner</a></td>
        <td>Improve your online safety with advice from experts</td>
    </tr>
    <tr>
        <td><a href="https://github.com/securitywithoutborders/hardentools">securitywithoutborders/hardentools</a></td>
        <td>Hardentools is a utility that disables a number of risky Windows features</td>
    </tr>
</table>

### Simulation

*Securtiy framework that can be used to simulate real attack scenario*

<table>
    <tr>
        <td><a href="https://github.com/alphasoc/flightsim">alphasoc/flightsim</a></td>
        <td>A utility to generate malicious network traffic and evaluate controls</td>
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
        <td><a href="https://github.com/uber-common/metta">uber-common/metta</a></td>
        <td>An information security preparedness tool to do adversarial simulation.</td>
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
        <td><a href="https://www.hyperiongray.com/dark-web-map/">Dark Web Map</a></td>
        <td>Dark Web Map - A visualization of 6.6k Tor onion services</td>
    </tr>
    <tr>
        <td><a href="https://github.com/DataSploit/datasploit">DataSploit/datasploit</a></td>
        <td>An #OSINT Framework to perform various recon techniques on Companies, People, Phone Number, Bitcoin Addresses, etc., aggregate all the raw data, and give data in multiple formats.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/fireeye/ReelPhish">fireeye/ReelPhish</a></td>
        <td>ReelPhish: A Real-Time Two-Factor Phishing Tool</td>
    </tr>
    <tr>
        <td><a href="https://www.mailsploit.com/index">Mailsploit</a></td>
        <td>TL;DR: Mailsploit is a collection of bugs in email clients that allow effective sender spoofing and code injection attacks. The spoofing is not detected by Mail Transfer Agents (MTA) aka email servers, therefore circumventing spoofing protection mechanisms such as DMARC (DKIM/SPF) or spam filters.</td>
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

*Vulnerable software, application, VM for research purpose and virtual environment for security testing*

<table>
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
        <td><a href="https://github.com/rapid7/hackazon">rapid7/hackazon</a></td>
        <td>A modern vulnerable web app</td>
    </tr>
    <tr>
        <td><a href="https://www.notsosecure.com/vulnerable-docker-vm/">Vulnerable Docker VM</a></td>
        <td>Ever fantasized about playing with docker misconfigurations, privilege escalation, etc. within a container?</td>
    </tr>
    <tr>
        <td><a href="https://github.com/sagishahar/lpeworkshop">sagishahar/lpeworkshop</a></td>
        <td>Windows / Linux Local Privilege Escalation Workshop</td>
    </tr>
    <tr>
        <td><a href="http://www.cis.syr.edu/~wedu/seed/labs.html">SEED Labs</a></td>
        <td>Various labs from SEED Project</td>
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
        <td><a href="https://github.com/jonluca/Anubis">jonluca/Anubis</a></td>
        <td>Subdomain enumeration and information gathering tool</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mazen160/bfac">mazen160/bfac</a></td>
        <td>BFAC (Backup File Artifacts Checker): An automated tool that checks for backup artifacts that may disclose the web-application's source code.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mindedsecurity/JStillery">mindedsecurity/JStillery</a></td>
        <td>Advanced JS Deobfuscation via Partial Evaluation.</td>
    </tr>
    <tr>
        <td><a href="https://publicwww.com/">Public WWW</a></td>
        <td>Source Code Search Engine</td>
    </tr>
</table>

### Windows

*Tools for Windows only*

<table>
    <tr>
        <td><a href="https://github.com/411Hall/JAWS">411Hall/JAWS</a></td>
        <td>JAWS is PowerShell script designed to help penetration testers (and CTFers) quickly identify potential privilege escalation vectors on Windows systems. It is written using PowerShell 2.0 so 'should' run on every Windows version since Windows 7.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/api0cradle/UltimateAppLockerByPassList">api0cradle/UltimateAppLockerByPassList</a></td>
        <td>The goal of this repository is to document the most common techniques to bypass AppLocker.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/DanMcInerney/icebreaker">DanMcInerney/icebreaker</a></td>
        <td>Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment</td>
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
        <td><a href="https://github.com/JohnLaTwC/PyPowerShellXray">JohnLaTwC/PyPowerShellXray</a></td>
        <td>Python script to decode common encoded PowerShell scripts</td>
    </tr>
    <tr>
        <td><a href="https://github.com/jonatan1024/clrinject">jonatan1024/clrinject</a></td>
        <td>Injects C# EXE or DLL Assembly into every CLR runtime and AppDomain of another process.</td>
    </tr>
    <tr>
        <td><a href="https://live.sysinternals.com/">Live Sysinternals Tools</a></td>
        <td>Live version of Sysinternal Suites</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mattifestation/PoCSubjectInterfacePackage">mattifestation/PoCSubjectInterfacePackage</a></td>
        <td>A PoC subject interface package (SIP) provider designed to educate about the required components of a SIP provider.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/sevagas/macro_pack">sevagas/macro_pack</a></td>
        <td>macro_pack is a tool used to automatize obfuscation and generation of MS Office documents for pentest, demo, and social engineering assessments. The goal of macro_pack is to simplify antimalware bypass and automatize the process from vba generation to final Office document generation.</td>
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
        <td><a href="https://github.com/shellster/DCSYNCMonitor">shellster/DCSYNCMonitor</a></td>
        <td>Monitors for DCSYNC and DCSHADOW attacks and create custom Windows Events for these events.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/secretsquirrel/SigThief">secretsquirrel/SigThief</a></td>
        <td>Stealing Signatures and Making One Invalid Signature at a Time</td>
    </tr>
    <tr>
        <td><a href="https://github.com/stephenfewer/ReflectiveDLLInjection">stephenfewer/ReflectiveDLLInjection</a></td>
        <td>Reflective DLL injection is a library injection technique in which the concept of reflective programming is employed to perform the loading of a library from memory into a host process</td>
    </tr>
</table>
