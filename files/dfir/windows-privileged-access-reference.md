# Windows Privileged Access Reference

<table>
  <tr>
    <th>Connectionmethod</th>
    <th>Logon type</th>
    <th>Reusable credentials on destination</th>
    <th>Comments</th>
  </tr>
  <tr>
    <td>Log on at console</td>
    <td>Interactive</td>
    <td>v</td>
    <td>Includes hardware remote access / lights-out cards and network KVMs.</td>
  </tr>
  <tr>
    <td>RUNAS</td>
    <td>Interactive</td>
    <td>v</td>
    <td></td>
  </tr>
  <tr>
    <td>RUNAS /NETWORK</td>
    <td>NewCredentials</td>
    <td>v</td>
    <td>Clones current LSA session for local access, but uses new credentials when connecting to network resources.</td>
  </tr>
  <tr>
    <td>Remote Desktop (success)</td>
    <td>RemoteInteractive</td>
    <td>v</td>
    <td>If the remote desktop client is configured to share local devices and resources, those may be compromised as well.</td>
  </tr>
  <tr>
    <td>Remote Desktop (failure - logon type was denied)</td>
    <td>RemoteInteractive</td>
    <td>-</td>
    <td>By default, if RDP logon fails credentials are only stored very briefly. This may not be the case if the computer is compromised.</td>
  </tr>
  <tr>
    <td>Net use * \\SERVER</td>
    <td>Network</td>
    <td>-</td>
    <td></td>
  </tr>
  <tr>
    <td>Net use * \\SERVER /u:user</td>
    <td>Network</td>
    <td>-</td>
    <td></td>
  </tr>
  <tr>
    <td>MMC snap-ins to remote computer</td>
    <td>Network</td>
    <td>-</td>
    <td>Example: Computer Management, Event Viewer, Device Manager, Services</td>
  </tr>
  <tr>
    <td>PowerShell WinRM</td>
    <td>Network</td>
    <td>-</td>
    <td>Example: Enter-PSSession server</td>
  </tr>
  <tr>
    <td>PowerShell WinRM with CredSSP</td>
    <td>NetworkClearText</td>
    <td>v</td>
    <td>New-PSSession server-Authentication Credssp-Credential cred</td>
  </tr>
  <tr>
    <td>PsExec without explicit creds</td>
    <td>Network</td>
    <td>-</td>
    <td>Example: PsExec \\server cmd</td>
  </tr>
  <tr>
    <td>PsExec with explicit creds</td>
    <td>Network + Interactive</td>
    <td>v</td>
    <td>PsExec \\server -u user -p pwd cmdCreates multiple logon sessions.</td>
  </tr>
  <tr>
    <td>Remote Registry</td>
    <td>Network</td>
    <td>-</td>
    <td></td>
  </tr>
  <tr>
    <td>Remote Desktop Gateway</td>
    <td>Network</td>
    <td>-</td>
    <td>Authenticating to Remote Desktop Gateway.</td>
  </tr>
  <tr>
    <td>Scheduled task</td>
    <td>Batch</td>
    <td>v</td>
    <td>Password will also be saved as LSA secret on disk.</td>
  </tr>
  <tr>
    <td>Run tools as a service</td>
    <td>Service</td>
    <td>v</td>
    <td>Password will also be saved as LSA secret on disk.</td>
  </tr>
  <tr>
    <td>Vulnerability scanners</td>
    <td>Network</td>
    <td>-</td>
    <td>Most scanners default to using network logons, though some vendors may implement non-network logons and introduce more credential theft risk.</td>
  </tr>
  <tr>
    <td>IIS "Basic Authentication"</td>
    <td>NetworkCleartext(IIS 6.0+)Interactive(prior to IIS 6.0)</td>
    <td>v</td>
    <td></td>
  </tr>
  <tr>
    <td>IIS "Integrated Windows Authentication"</td>
    <td>Network</td>
    <td>-</td>
    <td>NTLM and Kerberos Providers.</td>
  </tr>
</table>

<table>
  <tr>
    <th>Logon type</th>
    <th>#</th>
    <th>Authenticators accepted</th>
    <th>Reusable credentials in LSA session</th>
    <th>Examples</th>
  </tr>
  <tr>
    <td>Interactive (a.k.a., Logon locally)</td>
    <td>2</td>
    <td>Password, Smartcard,other</td>
    <td>Yes</td>
    <td>Console logon;RUNAS;Hardware remote control solutions (such as Network KVM or Remote Access / Lights-Out Card in server)IIS Basic Auth (before IIS 6.0)</td>
  </tr>
  <tr>
    <td>Network</td>
    <td>3</td>
    <td>Password,NT Hash,Kerberos ticket</td>
    <td>No (except if delegation is enabled, then Kerberos tickets present)</td>
    <td>NET USE;RPC calls;Remote registry;IIS integrated Windows auth;SQL Windows auth;</td>
  </tr>
  <tr>
    <td>Batch</td>
    <td>4</td>
    <td>Password (usually stored as LSA secret)</td>
    <td>Yes</td>
    <td>Scheduled tasks</td>
  </tr>
  <tr>
    <td>Service</td>
    <td>5</td>
    <td>Password (usually stored as LSA secret)</td>
    <td>Yes</td>
    <td>Windows services</td>
  </tr>
  <tr>
    <td>NetworkCleartext</td>
    <td>8</td>
    <td>Password</td>
    <td>Yes</td>
    <td>IIS Basic Auth (IIS 6.0 and newer);Windows PowerShell with CredSSP</td>
  </tr>
  <tr>
    <td>NewCredentials</td>
    <td>9</td>
    <td>Password</td>
    <td>Yes</td>
    <td>RUNAS /NETWORK</td>
  </tr>
  <tr>
    <td>RemoteInteractive</td>
    <td>10</td>
    <td>Password, Smartcard,other</td>
    <td>Yes</td>
    <td>Remote Desktop (formerly known as "Terminal Services")</td>
  </tr>
</table>


