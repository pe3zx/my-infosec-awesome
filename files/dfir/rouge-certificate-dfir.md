# Rouge Ceritifcation DFIR

Original article from: [Code Signing Certificate Cloning Attacks and Defenses](https://posts.specterops.io/code-signing-certificate-cloning-attacks-and-defenses-6f98657fc6ec) by SpecterOps

## Attacks

- Export all certificates in legitimate certificate chain, via Certificate Wizard, to disk. [Video](https://www.youtube.com/watch?time_continue=11&v=5rjJnxl50Dg).
- Signing target binary file with `New-SelfSignedCertificate` cmdlet in PowerShell. [Video](https://www.youtube.com/watch?v=qF6h2he5B7g)
    - Example of uses: [CertificateCloning.ps1](https://gist.github.com/mattifestation/b2e5c5b529e770c464f149e6020e280b#file-certificatecloning-ps1)
    - Remote trusting with WMI: [RemoteCertTrust.ps1](https://gist.github.com/mattifestation/429008d961bb719d5bd5ce262557bdbf#file-remotecerttrust-ps1)

## Detection

- Use Sysmon to monitor registry activity relates to certificate installation. Example config below.
    - Focus on *SetValue events where the TargetObject property ends with `<THUMBPRINT_VALUE>\Blob` as this indicates the direct installation or modification of a root certificate binary blob.*

<script src="https://gist.github.com/mattifestation/75d6117707bcf8c26845b3cbb6ad2b6b.js"></script>

- Investigate the content of certificate with powershell:

```powershell
Get-ChildItem -Path Cert:\ -Recurse | Where-Object { $_.Thumbprint -eq '1F3D38F280635F275BE92B87CF83E40E40458400' } | Format-List *
```

- Investigate and compare [authroot.stl](https://gist.github.com/mattifestation/c712e525109f786fbaf6ed576b8d2832) using [GetSTLCertHashes.ps1](https://gist.github.com/mattifestation/c712e525109f786fbaf6ed576b8d2832)

## Protection

- *While there may not be strong preventative mitigations for certificate installation as an admin, it is possible to prevent root certificate installation in the current user context by setting the following registry value:*

```
HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots - Flags (REG_DWORD) - 1
```
