# Detecting APT 28

- Using Event ID 4688 with Command Line logging enabled can trigger on Word calling cscript, wscript, and PowerShell as this is NOT normal.
- A DLL is used to infect the system using a batch file to load it which runs `RunDll32`.  Alerts on `RunDll32` using 4688 with Command Line logging could trigger on this behavior.
- If using Windows Firewall logging, which does NOT require using the Windows Firewall, Detecting the IPs used to communicate to the C2 server with 5156 events.
- Monitoring changes to well known AutoRun registry locations could detect this behavior using a 4657 event. An Autoruns scanner like LOG-MD can also discover these malicious changes. This payload used the following key: `HKCU\Environment\UserInitMprLogonScrip`
