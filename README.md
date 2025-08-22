# Certified Red Team Expert (CRTE) - Study Material

<div>
	<img src="https://media.eu.badgr.com/uploads/badges/assertion-I4s6LkhFQN21Hpr2iqqAKA.png?versionId=EiYPNRdVlobpjsFV4hiVnCJArm_zZTa9" alt="I pwned Red Team Lab" width="150" height="auto">
</div>

## Introduction

This repository is dedicated to documenting my preparation for the Certified Red Team Expert (CRTE) exam. It contains structured notes, in-depth technical explanations, and practical walkthroughs covering advanced topics in Active Directory security, exploitation, and forest-level attacks, aligning with the CRTE curriculum.

The materials are organized to build a step-by-step understanding of each technique, enriched with detailed examples, executed commands, and their corresponding outputs. This structure allows readers to follow the learning path and grasp the reasoning behind each attack without necessarily replicating every lab.

The repository covers a wide range of red teaming techniques beyond domain enumeration and privilege escalation, extending into cross-trust attacks, Active Directory Certificate Services (AD CS) exploitation, and advanced Kerberos abuse. Topics include:
- Domain Enumeration – users, computers, OUs, GPOs, ACLs, and trust relationships.
- Privilege Escalation – from local service abuse to domain privilege escalation via ACL and group abuse.
- Credential Extraction – from LSASS dumps (with MDE & WDAC bypasses) to replication-based attacks like DCSync.
- Kerberos Attacks – roasting attacks, delegation abuse, ticket forgery, and persistence techniques.
- AD CS (Certificate Services) Attacks – ESC1 exploitation.
- AD Trust Attacks – intra-forest and cross-forest abuses, including delegation, SID history injection, CredSSP abuse, SQL Server link abuse, and trust transitivity bypass.

Whether you are preparing for the CRTE certification or aiming to strengthen your expertise in advanced Active Directory red teaming, this repository serves both as a technical study guide and as a reference resource for offensive security professionals.

## Learning Path Topics

### 01 [Domain Enumeration](./01_crte_domain_enumeration.md)

- [x] Domain User Enumeration [Lab #01]
- [x] Domain Computer Enumeration [Lab #01]
- [x] Domain & Enterprise Admin Enumeration [Lab #01]
- [x] Kerberos Policy Enumeration [Lab #01]
- [x] OU Enumeration [Lab #02]
- [x] GPO Enumeration [Lab #02]
- [x] GPO Restricted Group Enumeration [Lab #02]
- [x] ACL Enumeration [Lab #03]
- [x] Domain & Forest Trust Enumeration [Lab #04]

### 02 [Privilege Escalation](./02_crte_privilege_escalation.md)

- [x] Local Privilege Escalation via Service Abuse [Lab #05.1]
- [x] Domain Privilege Escalation via ACL/Group Abuse [Lab #05.2]

### 03 [Credential Extraction](./03_crte_credential_extraction.md)

 - Disk-based Credential Extraction
	- [ ] Registry Hives (SAM, SECURITY, SYSTEM)
- Memory-based Credential Extraction
	- [x] LSASS Dump [Lab #09]
	- [x] LSASS Dump with MDE & WDAC Bypassing [Lab #10.2]
- AD Attribute-based Credential Extraction
	- [x] LAPS (Local Administrator Password Solution) Abuse [Lab #08]
	- [x] GMSA (Group Managed Service Account) Abuse [Lab #10.1]
- Replication-based Credential Extraction
	- [x] DCSync Attack via ACL Abuse

### 04 [Kerberos Attacks](./04_crte_kerberos_attacks.md)

- Kerberos Ticket Extraction Attacks
	- [ ] AS-REPRoasting Attack
	- [x] Kerberoasting Attack [Lab #06]
	- [x] Targeted Kerberoasting Attack [Lab #07]
- Kerberos Delegation Abuse
	- [x] Unconstrained Delegation Abuse [Lab #11]
	- [x] Constrained Delegation Abuse [Lab #12]
	- [x] RBCD (Resource-based Constrained Delegation) Abuse [Lab #13]
- Kerberos Ticket Persistence Attacks
	- [x] Golden Ticket Attack [Lab #14]
	- [x] Silver Ticket Attack [Lab #15]

### 05 [AD CS (Certificate Services) Attacks](./05_crte_ad_cs_attacks.md)

- [x] AD CS (Certificate Services) ESC1 Abuse [Lab #17]

### 06 [AD Trust Attacks](./06_crte_ad_trust_attacks.md)

- Intra-Forest Trust Attacks 
	- [x] Intra-Forest Unconstrained Delegation Abuse [Lab #18]
	- [x] Intra-Forest Azure AD Connect Abuse [Lab #19]
	- [x] Intra-Forest Trust Key Abuse via SID History Injection [Lab #20]
	- [x] Intra-Forest ExtraSID Attack [Lab #21]
- Cross-Forest Trust Attacks
	- [x] Cross-Forest Kerberoasting Attack [Lab #22]
	- [x] Cross-Forest Constrained Delegation Abuse [Lab #23]
	- [x] Cross-Forest Unconstrained Delegation Abuse [Lab #24]
	- [x] Cross-Forest Trust Account Abuse & SID History Injection [Lab #25]
	- [x] Cross-Forest SQL Server Link Abuse [Lab #26]
	- [x] Cross-Forest Foreign Security Principal & ACL Abuse [Lab #27]
	- [x] Cross-Forest PAM Trust Abuse [Lab #28]
	- [x] Cross-Forest Trust Account Abuse via CredSSP [Lab #29]
	- [x] Cross-Forest Trust Transitivity Bypass via Referral TGT [Lab #30]

---
---
