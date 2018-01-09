# Detecting DDE

Can be done by looking for Windows Event Logs on Microsoft Office category in event 300 which should be contain alerts display that an Office application launched something. By the way, if there is no pop-up displayed during the attack, there will be no alert in logs. In this case, incident responder can catach this attack by looking for new process event which must be configure by the following command. When process auditing turned on, suspicious event can be seen in Microsoft Windows Security auditing, event 4688.

```
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit /f /t REG_SZ /v ProcessCreationIncludeCmdLine_Enabled=1

auditpol /set /Category:"Detailed Tracking" /subcategory:"Process Creation" /success:enable /failure:enable
```
