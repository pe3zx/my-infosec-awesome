# My Awesome

[![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)
[![travis-banner](https://travis-ci.org/pe3zx/my-awesome.svg?branch=master)](https://travis-ci.org/pe3zx/my-awesome)

My curated list of awesome links, resources and tools

- [My Awesome](#my-awesome)
- [Articles](#article)
    - [Awesome](#awesome)
    - [Anti Forensics](#anti-forensics)
    - [Certifications](#certifications)
    - [Digital Forensics and Incident Response](#digital-forensics-and-incident-response)
    - [Exploitation](#exploitation)
    - [Malware Analysis](#malware-analysis)
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
    - [Social Engineering](#social-engineering)
    - [Vulnerable](#vulnerable)
    - [Web Application Security](#web-application-security-1)
    - [Windows](#windows)

---

## Articles

### Awesome

- [dsasmblr/game-hacking - Tutorials, tools, and more as related to reverse engineering video games.](https://github.com/dsasmblr/game-hacking)

### Anti Forensics

- [Removing Your PDF Metadata & Protecting PDF Files](https://blog.joshlemon.com.au/protecting-your-pdf-files-and-metadata/)
    - Mirror copy of the script in this article is available at [files/anti-forensics/cleaning-pdf.sh](files/anti-forensics/cleaning-pdf.sh)

### Certifications

- OSCE
    - [OSCE/CTP PREP GUIDE](https://tulpa-security.com/2017/07/18/288/)
    - [OSCE Study Plan](http://www.abatchy.com/2017/03/osce-study-plan.html)
- OSCP
    - [Offensive Security Certified Professional (OSCP) Review](https://www.jimwilbur.com/2017/07/oscp-review/)
    - [OSCP Course & Exam Preparation](https://411hall.github.io/OSCP-Preparation/)

### Digital Forensics and Incident Response

- [Beyond good ol' Run key Series](http://www.hexacorn.com/blog/?s=Beyond+good+ol%E2%80%99+Run+key%2C)
	- Mirror copy and TLDR version of articles are available at [files/dfir/beyod-good-ol-run-key.md](files/dfir/beyond-good-ol-run-key.md)
- [Certificate Chain Cloning and Cloned Root Trust Attacks](https://posts.specterops.io/code-signing-certificate-cloning-attacks-and-defenses-6f98657fc6ec)
    - Mirror copy (TLDR version) of the article is available at [files/dfir/rouge-certificate-dfir.md](files/dfir/rouge-certificate-dfir.md)
- [Windows Privileged Access Reference](https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access-reference-material#ATLT_BM)
	- Mirror copy of the table is available at [files/dfir/windows-privileged-access-reference.md](files/dfir/windows-privileged-access-reference.md)

### Exploitation

- [Guest Diary (Etay Nir) Kernel Hooking Basics](https://isc.sans.edu/forums/diary/Guest+Diary+Etay+Nir+Kernel+Hooking+Basics/23155/)

#### Platforms

##### ARM Exploitation

- [ARM exploitation for IoT – Episode 1](https://quequero.org/2017/07/arm-exploitation-iot-episode-1/)
- [ARM exploitation for IoT – Episode 2](https://quequero.org/2017/09/arm-exploitation-iot-episode-2/)
- [ARM exploitation for IoT – Episode 3](https://quequero.org/2017/11/arm-exploitation-iot-episode-3/)

#### Software Exploitation

##### Linux

- [64-bit Linux Return-Oriented Programming](https://crypto.stanford.edu/~blynn/rop/)
- [Blocking double-free in Linux kernel](http://blog.ptsecurity.com/2017/08/linux-block-double-free.html)
- [CVE-2016-2384: exploiting a double-free in the usb-midi linux kernel driver](https://xairy.github.io/blog/2016/cve-2016-2384)
- [CVE-2017-2636: exploit the race condition in the n_hdlc Linux kernel driver bypassing SMEP](https://a13xp0p0v.github.io/2017/03/24/CVE-2017-2636.html)
- [Dirty COW and why lying is bad even if you are the Linux kernel](https://chao-tic.github.io/blog/2017/05/24/dirty-cow)
- [Enumeration for Linux Privilege Escalation](https://0x00sec.org/t/enumeration-for-linux-privilege-escalation/1959)
- [Escaping Docker container using waitid() – CVE-2017-5123](https://www.twistlock.com/2017/12/27/escaping-docker-container-using-waitid-cve-2017-5123/)
- [Exploit Dev 0x01 | 64-bit Linux Stack Buffer Overflow](http://badbytes.io/2017/02/15/exploit-dev-0x01-64-bit-linux-stack-buffer-overflow/)
- [Exploiting the Linux kernel via packet sockets](https://googleprojectzero.blogspot.com/2017/05/exploiting-linux-kernel-via-packet.html)
- [Kernel Exploitation | Dereferencing a NULL pointer!](https://0x00sec.org/t/kernel-exploitation-dereferencing-a-null-pointer/3850)
- [Linux (x86) Exploit Development Series](https://sploitfun.wordpress.com/2015/06/26/linux-x86-exploit-development-tutorial-series/)
- [Linux Heap Exploitation Intro Series: The magicians cape – 1 Byte Overflow](https://sensepost.com/blog/2017/linux-heap-exploitation-intro-series-the-magicians-cape-1-byte-overflow/)
- [Linux Heap Exploitation Intro Series: Used and Abused – Use After Free](https://sensepost.com/blog/2017/linux-heap-exploitation-intro-series-used-and-abused-use-after-free/)
- [Linux Kernel ROP - Ropping your way to # (Part 1)](https://www.trustwave.com/Resources/SpiderLabs-Blog/Linux-Kernel-ROP---Ropping-your-way-to---(Part-1)/)
- [Linux Kernel ROP - Ropping your way to # (Part 2)](https://www.trustwave.com/Resources/SpiderLabs-Blog/Linux-Kernel-ROP---Ropping-your-way-to---(Part-2)/)
- [Linux Kernel Vulnerability Can Lead to Privilege Escalation: Analyzing CVE-2017-1000112](https://securingtomorrow.mcafee.com/mcafee-labs/linux-kernel-vulnerability-can-lead-to-privilege-escalation-analyzing-cve-2017-1000112/#sf118405156)
- [Linux System Call Table](http://thevivekpandey.github.io/posts/2017-09-25-linux-system-calls.html)
- [Reversing DirtyC0W](http://blog.tetrane.com/2017/09/dirtyc0w-1.html)
- [xairy/linux-kernel-exploitation](https://github.com/xairy/linux-kernel-exploitation)

##### Windows

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
- [Kernel Debugging 101 – Part1](https://vvalien1.wordpress.com/2016/12/26/kernel-debugging-101/)
- [Kernel Debugging 101 – Part2](https://vvalien1.wordpress.com/2017/01/01/kernel-debugging-101-part2/)
- [Kernel Debugging 101 – Part3](https://vvalien1.wordpress.com/2017/01/01/kernel-debugging-101-part3/)
- [Kernel Exploitation Case Study - "Wild" Pool Overflow on Win10 x64 RS2 (CVE-2016-3309 Reloaded)](https://siberas.de/blog/2017/10/05/exploitation_case_study_wild_pool_overflow_CVE-2016-3309_reloaded.html)
- [Kernel Pool Overflow Exploitation In Real World – Windows 7](http://trackwatch.com/kernel-pool-overflow-exploitation-in-real-world-windows-7/)
- [Kernel Pool Overflow Exploitation In Real World – Windows 10](http://trackwatch.com/kernel-pool-overflow-exploitation-in-real-world-windows-10/)
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
- [sam-b/windows_kernel_resources](https://github.com/sam-b/windows_kernel_resources)
- [Sharks in the Pool :: Mixed Object Exploitation in the Windows Kernel Pool](http://srcincite.io/blog/2017/09/06/sharks-in-the-pool-mixed-object-exploitation-in-the-windows-kernel-pool.html)
- [Signing Mimikatz](https://twitter.com/subTee/status/912769644473098240)
- [Skeleton in the closet. MS Office vulnerability you didn’t know about](https://embedi.com/blog/skeleton-closet-ms-office-vulnerability-you-didnt-know-about/)
- [Starting with Windows Kernel Exploitation – part 1 – setting up the lab](https://hshrzd.wordpress.com/2017/05/28/starting-with-windows-kernel-exploitation-part-1-setting-up-the-lab/)
- [Starting with Windows Kernel Exploitation – part 2 – getting familiar with HackSys Extreme Vulnerable Driver](https://hshrzd.wordpress.com/2017/06/05/starting-with-windows-kernel-exploitation-part-2/)
- [Starting with Windows Kernel Exploitation – part 3 – stealing the Access Token](https://hshrzd.wordpress.com/2017/06/22/starting-with-windows-kernel-exploitation-part-3-stealing-the-access-token/)
- [Tales from the MSRC: from pixels to POC](https://blogs.technet.microsoft.com/srd/2017/06/20/tales-from-the-msrc-from-pixels-to-poc/)
- [The Art of Becoming TrustedInstaller](https://tyranidslair.blogspot.co.id/2017/08/the-art-of-becoming-trustedinstaller.html)
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
- [Windows Kernel Exploitation – Arbitrary Overwrite](https://osandamalith.com/2017/06/14/windows-kernel-exploitation-arbitrary-overwrite/)
- [Windows Kernel Exploitation : This Time Font hunt you down in 4 bytes](https://www.slideshare.net/PeterHlavaty/windows-kernel-exploitation-this-time-font-hunt-you-down-in-4-bytes)
- [Zero Day Zen Garden: Windows Exploit Development - Part 0 [Dev Setup & Advice]](http://www.shogunlab.com/blog/2017/08/11/zdzg-windows-exploit-0.html)
- [Zero Day Zen Garden: Windows Exploit Development - Part 1 [Stack Buffer Overflow Intro]](http://www.shogunlab.com/blog/2017/08/19/zdzg-windows-exploit-1.html)
- [Zero Day Zen Garden: Windows Exploit Development - Part 2 [JMP to Locate Shellcode]](http://www.shogunlab.com/blog/2017/08/26/zdzg-windows-exploit-2.html)
- [Zero Day Zen Garden: Windows Exploit Development - Part 3 [Egghunter to Locate Shellcode]](http://www.shogunlab.com/blog/2017/09/02/zdzg-windows-exploit-3.html)

#### Techniques

##### Bypassing ASLR

*Any related techniques for ASLR bypassing*

- [Bypassing ASLR – Part I](https://sploitfun.wordpress.com/2015/05/08/bypassing-aslr-part-i/)
- [Bypassing ASLR – Part II](https://sploitfun.wordpress.com/2015/05/08/bypassing-aslr-part-ii/)
- [Bypassing ASLR – Part III](https://sploitfun.wordpress.com/2015/05/08/bypassing-aslr-part-iii/)

##### Format Strings

*Format strings exploitation*

- [Format String Exploitation Primer](https://borgandrew.blogspot.com/2017/01/h1-margin-bottom-0.html)
- [X86 EXPLOITATION 101: “FORMAT STRINGS” – I’LL TELL YA WHAT TO SAY](https://gbmaster.wordpress.com/2015/12/08/x86-exploitation-101-format-strings-ill-tell-ya-what-to-say/)

##### Heap Exploitation

*Heap exploitation related articles and tutorials*

- [Heap Exploitation](https://www.gitbook.com/book/dhavalkapil/heap-exploitation/details)
- [Heap Exploitation ~ Fastbin Attack](https://0x00sec.org/t/heap-exploitation-fastbin-attack/3627)
- [Heap Exploitation ~ Abusing Use-After-Free](https://0x00sec.org/t/heap-exploitation-abusing-use-after-free/3580)
- [Heap overflow using unlink](https://sploitfun.wordpress.com/2015/02/26/heap-overflow-using-unlink/)
- [Heap overflow using Malloc Maleficarum](https://sploitfun.wordpress.com/2015/03/04/heap-overflow-using-malloc-maleficarum/)
- [shellphishi/how2heap](https://github.com/shellphish/how2heap)
- [X86 EXPLOITATION 101: HEAP OVERFLOWS… UNLINK ME, WOULD YOU PLEASE?](https://gbmaster.wordpress.com/2014/08/11/x86-exploitation-101-heap-overflows-unlink-me-would-you-please/)
- [X86 EXPLOITATION 101: THIS IS THE FIRST WITCHY HOUSE](https://gbmaster.wordpress.com/2014/08/24/x86-exploitation-101-this-is-the-first-witchy-house/)
- [X86 EXPLOITATION 101: “HOUSE OF MIND” – UNDEAD AND LOVING IT…](https://gbmaster.wordpress.com/2015/06/15/x86-exploitation-101-house-of-mind-undead-and-loving-it/)
- [X86 EXPLOITATION 101: “HOUSE OF FORCE” – JEDI OVERFLOW](https://gbmaster.wordpress.com/2015/06/28/x86-exploitation-101-house-of-force-jedi-overflow/)
- [X86 EXPLOITATION 101: “HOUSE OF LORE” – PEOPLE AND TRADITIONS](https://gbmaster.wordpress.com/2015/07/16/x86-exploitation-101-house-of-lore-people-and-traditions/)
- [Understanding the Heap & Exploiting Heap Overflows](http://www.mathyvanhoef.com/2013/02/understanding-heap-exploiting-heap.html)

##### Integer Overflow

*Integer overflow epxloitaion*

- [Integer Overflow](https://sploitfun.wordpress.com/2015/06/23/integer-overflow/)
- [X86 EXPLOITATION 101: “INTEGER OVERFLOW” – ADDING ONE MORE… AAAAAAAAAAAND IT’S GONE](https://gbmaster.wordpress.com/2015/08/13/x86-exploitation-101-integer-overflow-adding-one-more-aaaaaaaaaaand-its-gone/)

##### Return Oriented Programming

*ROP cases and guidelines*

- [A ROP Primer solution 64-bit style](https://blog.techorganic.com/2015/10/09/a-rop-primer-solution-64-bit-style/)
- [Blind Return Oriented Programming 102](https://oddcoder.com/BROP-102/)
- [Intro to ROP: ROP Emporium — Split](https://medium.com/@iseethieves/intro-to-rop-rop-emporium-split-9b2ec6d4db08)
- [Introduction to Return Oriented Programming (ROP)](https://ketansingh.net/Introduction-to-Return-Oriented-Programming-ROP/index.html)
- [Return-Oriented Programming (ROP) 101](https://www.tripwire.com/state-of-security/off-topic/vert-vuln-school-return-oriented-programming-rop-101/)
- [ROP Emporium](https://ropemporium.com/)
- [ROP Primer](https://speakerdeck.com/barrebas/rop-primer)
- [Sigreturn Oriented Programming](https://0x00sec.org/t/srop-signals-you-say/2890)

##### return-to-libc

*return-to-libc techniques*

- [Bypassing NX bit using return-to-libc](https://sploitfun.wordpress.com/2015/05/08/bypassing-nx-bit-using-return-to-libc/)
- [Bypassing NX bit using chained return-to-libc](https://sploitfun.wordpress.com/2015/05/08/bypassing-nx-bit-using-chained-return-to-libc/)

#### Shellcoding

*Art of crafting shellcode*

- [SLAE: Bind TCP Shell – Assignment 1](http://0xdeadcode.se/archives/637)
- [SLAE: Reverse TCP Shell – Assignment 2](http://0xdeadcode.se/archives/689)
- [SLAE: Egg Hunter – Assignment 3](http://0xdeadcode.se/archives/707)

##### Stack Exploitation

*Corrupt the stack*

- [Buffer Overflow Explotation](https://0x00sec.org/t/buffer-overflow-explotation/3846/1)
- [Classic Stack Based Buffer Overflow](https://sploitfun.wordpress.com/2015/05/08/classic-stack-based-buffer-overflow/)
- [Exploiting 1-byte buffer overflows](https://www.welivesecurity.com/2016/05/10/exploiting-1-byte-buffer-overflows/)
- [PLAYING WITH CANARIES](https://www.elttam.com.au/blog/playing-with-canaries/)
- [Simple buffer overflow on a modern system](http://liveoverflow.com/blog/stack0_buffer_overflow_on_ubuntu.html)
- [Stack Clashing for Fun and Profit](http://nullprogram.com/blog/2017/06/21/)
- [When is something overflowing](https://www.slideshare.net/PeterHlavaty/overflow-48573748)
- [X86 EXPLOITATION 101: WHEN THE STACK GETS OVER ITS HEAD](https://gbmaster.wordpress.com/2014/06/18/x86-exploitation-101-when-the-stack-gets-over-its-head/)
- [X86 EXPLOITATION 101: BORN IN A SHELL](https://gbmaster.wordpress.com/2014/07/01/x86-exploitation-101-born-in-a-shell/)
- [X86 EXPLOITATION 101: “HOUSE OF SPIRIT” – FRIENDLY STACK OVERFLOW](https://gbmaster.wordpress.com/2015/07/21/x86-exploitation-101-house-of-spirit-friendly-stack-overflow/)
- [Your First Buffer Overflow](https://medium.com/@mackwage/your-first-buffer-overflow-89141a9a2941)


##### Trusted Execution

*Various techniques to execute malicious binary with trusted, bypassing security protection*

- [Execute unsigned binary via signed Tracker.exe (required Tracker.exe and TrackerUI.dll)](https://twitter.com/sudhanshu_c/status/943011972261412864?ref_src=twcamp%5Eshare%7Ctwsrc%5Eios%7Ctwgr%5Eother)

##### Use-After-Free

*Use-After-Free related arcitles*

- [Use-After-Free](https://sploitfun.wordpress.com/2015/06/16/use-after-free/)

### Malware Analysis

- [baderj/domain_generation_algorithms - Some results of my DGA reversing efforts](https://github.com/baderj/domain_generation_algorithms)
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
- Use `Trust access to the VBA project object model` to circumvent security control of VBA script on Microsoft Office
    - Original stories can be found on [MS Office Built-In Feature Could be Exploited to Create Self-Replicating Malware](https://thehackernews.com/2017/11/ms-office-macro-malware.html) and [Virus Bulletin June 2001](https://www.virusbulletin.com/uploads/pdf/magazine/2001/200106.pdf)
    - The option `Trust access to the VBA project object model`, according to [Office Support](https://support.office.com/en-us/article/Enable-or-disable-macros-in-Office-files-12b036fd-d140-4e74-b45e-16fed1a7e5c6), can be used to allow programmatic access to the VBA object model from an automation client. This option is controlled by registry key available on `HKCU\Software\Microsoft\Office\14.0\Word\Security` with `AccessVBOM`, `0` for disable and `1` for enable.

#### Malware Variants

- Badrabbit
    - [‘BadRabbit’ Ransomware Burrows Into Russia, Ukraine](https://securingtomorrow.mcafee.com/mcafee-labs/badrabbit-ransomware-burrows-russia-ukraine/)
    - [BadRabbit: a closer look at the new version of Petya/NotPetya](https://blog.malwarebytes.com/threat-analysis/2017/10/badrabbit-closer-look-new-version-petyanotpetya/)
    - [Bad Rabbit: Not-Petya is back with improved ransomware](https://www.welivesecurity.com/2017/10/24/bad-rabbit-not-petya-back/)
    - [Bad Rabbit – A New Ransomware Outbreak Targeting Ukraine and Russia.](https://blog.checkpoint.com/2017/10/24/bad-rabbit-new-ransomware-outbreak-targeting-ukraine-russia/)
    - [Bad Rabbit ransomware](https://securelist.com/bad-rabbit-ransomware/82851/)
    - [Bad Rabbit Ransomware Spreads via Network, Hits Ukraine and Russia](http://blog.trendmicro.com/trendlabs-security-intelligence/bad-rabbit-ransomware-spreads-via-network-hits-ukraine-russia/)
    - [Bad Rabbit Ransomware Strikes Ukraine, Likely related to GoldenEye](https://labs.bitdefender.com/2017/10/bad-rabbit-ransomware-strikes-ukraine-likely-related-to-goldeneye/)
    - [NotPetya Returns as Bad Rabbit](http://www.intezer.com/notpetya-returns-bad-rabbit/)
    - [Threat Spotlight: Follow the Bad Rabbit](http://blog.talosintelligence.com/2017/10/bad-rabbit.html)
- Bankbot
    - [A Look Into The New Strain of BankBot](https://blog.fortinet.com/2017/09/19/a-look-into-the-new-strain-of-bankbot)
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

### Reverse Engineering

- [A Gentle Primer on Reverse Engineering](https://emily.st/2015/01/27/reverse-engineering/)
- [FAQ: How to learn reverse-engineering?](http://gynvael.coldwind.pl/?id=664)
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

### SQL Injection

- [NetSPI SQL Injection Wiki](https://sqlwiki.netspi.com/)

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
        <td>CVE-2017-15944</td>
        <td>Palo Alto Networks PAN-OS before 6.1.19, 7.0.x before 7.0.19, 7.1.x before 7.1.14, and 8.0.x before 8.0.6 allows remote attackers to execute arbitrary code via vectors involving the management interface.
            <ul>
                <li><a href="http://seclists.org/fulldisclosure/2017/Dec/38">CVE-2017-15944: Palo Alto Networks firewalls remote root code execution</a></li>
                <li><a href="http://seclists.org/fulldisclosure/2017/Dec/65">Exploit verification script</a></li>
            </ul>
        </td>
    </tr>
    <tr>
        <td>CVE-2017-17215</td>
        <td>
            <ul>
                <li><a href="https://www.exploit-db.com/exploits/43414/">Huawei Router HG532 - Arbitrary Command Execution</a></li>
            </ul>
        </td>
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
        <td><a href="https://malpedia.caad.fkie.fraunhofer.de/">Malpedia</a></td>
        <td>The primary goal of Malpedia is to provide a resource for rapid identification and actionable context when investigating malware. Openness to curated contributions shall ensure an accountable level of quality in order to foster meaningful and reproducible research.</td>
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
        <td><a href="https://github.com/airbus-seclab/bincat">airbus-seclab/bincat</a></td>
        <td>Binary code static analyser, with IDA integration. Performs value and taint analysis, type reconstruction.</td>
    </tr>
    <tr>
        <td><a href="https://github.com/fireeye/SimplifyGraph">fireeye/SimplifyGraph</a></td>
        <td>IDA Pro plugin to assist with complex graphs</td>
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
        <td><a href="https://securityplanner.org/">Security Planner</a></td>
        <td>Improve your online safety with advice from experts</td>
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
        <td><a href="https://github.com/clong/DetectionLab">clong/DetectionLab</a></td>
        <td>Vagrant & Packer scripts to build a lab environment complete with security tooling and logging best practices</td>
    </tr>
    <tr>
        <td><a href="https://github.com/mitre/caldera">mitre/caldera</a></td>
        <td>The CALDERA automated adversary emulation system</td>
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
        <td><a href="https://github.com/jonluca/Anubis">jonluca/Anubis</a></td>
        <td>Subdomain enumeration and information gathering tool</td>
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
        <td><a href="https://github.com/411Hall/JAWS">411Hall/JAWS</a></td>
        <td>JAWS is PowerShell script designed to help penetration testers (and CTFers) quickly identify potential privilege escalation vectors on Windows systems. It is written using PowerShell 2.0 so 'should' run on every Windows version since Windows 7.</td>
    </tr>
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
        <td><a href="https://live.sysinternals.com/">Live Sysinternals Tools</a></td>
        <td>Live version of Sysinternal Suites</td>
    </tr>
    <tr>
        <td><a href="https://github.com/sevagas/macro_pack">sevagas/macro_pack</a></td>
        <td>macro_pack is a tool used to automatize obfuscation and generation of MS Office documents for pentest, demo, and social engineering assessments. The goal of macro_pack is to simplify antimalware bypass and automatize the process from vba generation to final Office document generation.</td>
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
        <td><a href="https://github.com/secretsquirrel/SigThief">secretsquirrel/SigThief</a></td>
        <td>Stealing Signatures and Making One Invalid Signature at a Time</td>
    </tr>
</table>
