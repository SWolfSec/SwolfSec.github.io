---
published: true
layout: post
title: Investigating and Detecting Resource-Based Constrained Delegation Attacks
subtitle: Detecting RBCD abuse in a sea of Active Directory logs
tags: [kerberos] [RBCD] [ACL]
comments: false
share-img:  https://swolfsec.github.io/assets/img/img_2023-RBCD/RBCD_DetectionLogic.PNG
---
> By Stephan Wolfert

> **_TL:DR_** Resource-Based Constrained Delegation abuse is a privilege escalation technique which can be visible and detectable! Where do we start for detectability?

## What is Resource-Based Constrained Delegation (“RBCD”)?

RBCD is a security feature which allows an administrator to delegate permissions in order to securely manage resources. Essentially, RBCD allows an object to access specific resources with the ability to impersonate other users and their permissions. The object (or computer account in our example) which is allowed to impersonate others to a resource is specified in the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute. The abuse scenario comes in when an attacker has write privileges over the attribute where it can be modified to specify an object they control or create, therefore allowing them to impersonate any user to that resource. The original attack path and details can be found [here](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html) written by Elad Shamir. We won't cover performing this attack here and I strongly suggest if you are interested in this topic you take the time to read Elad's explanation. Instead here we will focus on discoverability and detection. 

## Investigating RBCD Attacks

In order to investigate RBCD and detect on RBCD abuse, we must first identify the stages of the attack and how they translate to the logs. Here we will primarily rely on Windows Event Logs although there may be alternative methods that help in identifying this type of abuse, for example Identity Threat Detection and Response tools. A simplified explanation of the impact in our scenario is a low-privileged user is able to access a Domain Controller as any user in the domain (yes, including Domain Admins).

We will focus on two primary event IDs; 4769 (A Kerberos service ticket was requested), and 5136 (A directory service object was modified). Both of these logs can be found on the Domain Controller. Event ID 4741 (A computer account was created) may also be relevant but we will touch on this later on. 

In our example, the user `bfarmer` is a part of a domain group which has Write privileges to properties on a Domain Controller (`DC-2`). We also have local admin on `WKSTN-2` which gives us access to a principal with an SPN (an important part of this attack although local admin is not totally necessary).

The first attack path goes like this:

- Dump a TGT for the `WKSTN-2` computer account
- Modify `msDS-AllowedToActOnBehalfOfOtherIdentity` on `DC-2` to the SID for `WKSTN-2`
- Perform S4U (Service For User) using 3 key data points
    - Our computer account: `WKSTN-2$`
    - A specified user to impersonate (Domain Admin `nlamb`)
    - The target SPN (cifs on `DC-2`)
- Use the generated TGS to access `DC-2`

The modification of the `msDS-AllowedToActOnBehalfOfOtherIdentity` AD attribute can be identified in the 5136 event ID. The Account Name (`bfarmer` the user altering the attribute) and the Object DN (`DC-2`, where the attribute is being modified) are two key data points we will need to remember. Note baselining these events and how common they are in your environment is important, is there a scenario where this attribute is modified often? If so, can we identify low-privileged or abnormal users in general making changes to that attribute?   

![RBCD_1](https://swolfsec.github.io/assets/img/img_2023-RBCD/RBCD_1.PNG){: .mx-auto.d-block :}

Following the modification of the AD attribute, there are two 4769 events generated in succession as part of the Service for User to Self (S4U2Self) & Service for User to Proxy (S4U2Proxy) requests.

![RBCD_2](https://swolfsec.github.io/assets/img/img_2023-RBCD/RBCD_2.PNG){: .mx-auto.d-block :}

The first service ticket request is for `WKSTN-2$` with a “Service Name” of `WKSTN-2$`. This is the initial S4U2Self request. At this point in the S4U request, we’ve requested a TGS for the user we are impersonating `nlamb` to `WKSTN-2$`. The Ticket Options of `0x40800018` are common for this S4U2Self ticket request. Another key aspect of this log is the Logon GUID which can be used to track similar events including the S4U2Proxy TGS request which we will discuss next.

![RBCD_3](https://swolfsec.github.io/assets/img/img_2023-RBCD/RBCD_3.PNG){: .mx-auto.d-block :}

The second 4769 event log, which occurs at the same time as the previous request, is the impersonation of `nlamb` to the target SPN, `cifs/dc-2.dev.cyberbotic.io`. This is the ticket granting us access as the Domain Administrator to the cifs service principal on the Domain Controller. The account name is our source `WKSTN-2$`, while the “Service Name” is `DC-2$`.

The Ticket Options of `0x40820010` are common for this S4U2Proxy ticket request. S4U2Proxy is essentially a service ticket to another service on behalf of a user, service ticket for `WKSTN-2$` to `cifs/dc-2.dev.cyberbotic.io` on behalf of `nlamb`.

Lastly, the presence of `WKSTN-2$@DEV.CYBERBOTIC.IO` in the Transited Services field. Your experience may vary but the Transited Services field in my experience is very often a blank value or rather "-". The Transited Services field is directly related to Constrained Delegation and Microsoft describes it as a field which contains “a list of SPNs which were requested if constrained Kerberos delegation was used”. If you get nothing else from this blog, scrutinize ticket requests with Transited Services filled out. 

![RBCD_4](https://swolfsec.github.io/assets/img/img_2023-RBCD/RBCD_4.PNG){: .mx-auto.d-block :}

We have our three (3) Windows Event Logs to identify RBCD. Let's theorize about detectability. 

## Detection Logic

All three (3) of these events play an important part in identifying RBCD abuse although some may be higher fidelity then others. With this in mind we can consider them independently and then how they relate to each other. This detection logic may look daunting at first but breaking it down in this way step by step can help us get to better detections with varying levels of confidence on the way. This is absolutely important to managing the quality of our detections and balancing between alert fatigue or a lack of alerting. 

![RBCD_DetectionLogic](https://swolfsec.github.io/assets/img/img_2023-RBCD/RBCD_DetectionLogic.PNG){: .mx-auto.d-block :}

Please note, this detection logic here may vary based on your environment but the theory will stay the same. Additionally, there may be a point in this flow where you still want to push a detection or alert for instance if 5136 for the attribute `msDS-AllowedToActOnBehalfOfOtherIdentity` is extremely rare in your environment, or flat out non-existent, you may not care to check if the Account name is an uncommon or low-privileged user. Alternatively if this is a rather normal occurrence, you may wish to include an exclusion for that specific account performing that operation (as always be careful with exclusions). It probably goes without saying but every environment is different and I strongly encourage baselining before implementing detections.  

The primary goal here is to develop detections of varying criticality that will alert us of RBCD abuse. We don't want to ignore any scenario where ALL of our conditions are not true but we also don't want to alert on every 4769 ticket request. For example, the S4U2Self request may be more noisy or difficult to identify on its own, but in conjunction with the S4U2Proxy it can be higher fidelity.  

## No Local Admin? Create a Domain Computer Account!

Mentioned previously was event ID 4741 (A computer account was created). In the first part of our example, we had local admin to a system, `WKSTN-2`, that we could then use to perform RBCD. If we did not have this access there is another way. The Active Directory attribute ms-ds-machineaccountquota provides a value which specifies the number of computer accounts that any given account can create. By default this is set to 10 for all users, yes even low-privileged users. I recommend setting it to 0, or identifying which accounts require the ability to create computer accounts and setting it to the necessary amount while set everyone else’s to 0.

![RBCD_5](https://swolfsec.github.io/assets/img/img_2023-RBCD/RBCD_5.PNG){: .mx-auto.d-block :}

In our scenario, it is set to the default and the attack looks pretty much the same as before. There is one additional step that can provide us visibility. I'll reiterate the logs here to show that multiple attack scenarios still trigger on the same events. Instead of dumping the local kerberos tickets, we have two additional steps; 1. Create the computer account and 2. request a TGT for that computer account.

To identify the creation of the computer account Auditing for Computer Account Management must be enabled. With this enabled we will now be logging event id 4741 where we can monitor for abnormal computer account creations.

![RBCD_6](https://swolfsec.github.io/assets/img/img_2023-RBCD/RBCD_6.PNG){: .mx-auto.d-block :}

After creating our computer account, we must request a TGT. In this case, the TGT request is not much different then normal requests and therefore is not very detectable but could prove useful in a historical investigation and is worth checking for.

![RBCD_7](https://swolfsec.github.io/assets/img/img_2023-RBCD/RBCD_7.PNG){: .mx-auto.d-block :}

Then again we have the same flow of events, 5136 showing the msDS-AllowedToActOnBehalfOfOtherIdentity modification, the 4769 computer account service ticket request (S4U2Self), then finally the 4769 with Transited Services (S4U2Proxy).

![RBCD_8](https://swolfsec.github.io/assets/img/img_2023-RBCD/RBCD_8.PNG){: .mx-auto.d-block :}

![RBCD_9](https://swolfsec.github.io/assets/img/img_2023-RBCD/RBCD_9.PNG){: .mx-auto.d-block :}

In the event that a Domain Computer object was created to facilitate RBCD rather then using local administrative access, we can incorporate a 4th lane to our detection flow. Since the `MachineAccountQuota` can be used in a few different attacks, your detection strategy for normal users creating domain computer objects may be a bit more broad. But in specific relation to RBCD, this 4th lane would look for 4741 event IDs where a computer account was created and then used as the Account Name / Service Name in the S4U2Self request or was used in a Account Name / Transited Services field of S4U2Proxy request in the 4769s. And lastly, maybe the account identified in the 4741, which created the computer object, is also the account which updates `msDS-AllowedToActOnBehalfOfOtherIdentity` now linking the event id 4741 to 5136s as well giving us two opportunities for early detections.

## Example Searches
  

#### Kerberos Service Ticket Request - S4U2Proxy

##### KQL

```
event.code : 4769 and winlog.event_data.TicketOptions : 0x40820010 and NOT winlog.event_data.TransmittedServices : -
```

![RBCD_10](https://swolfsec.github.io/assets/img/img_2023-RBCD/RBCD_10.PNG){: .mx-auto.d-block :}

##### Splunk

```
index=win EventCode=4769 TicketOptions=0x40820010 NOT TransitedServices="-"
```

#### msDS-AllowedToActOnBehalfOfOtherIdentity Modification

```

event.code : "5136" and winlog.event_data.AttributeLDAPDisplayName : "msDS-AllowedToActOnBehalfOfOtherIdentity"

```
![RBCD_11](https://swolfsec.github.io/assets/img/img_2023-RBCD/RBCD_11.PNG){: .mx-auto.d-block :}

##### Splunk

```
index=win EventCode=5136 LDAPDisplayName=msDS-AllowedToActOnBehalfOfOtherIdentity
```


## References

https://eladshamir.com/2019/01/28/Wagging-the-Dog.html
https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution
https://training.zeropointsecurity.co.uk/courses/red-team-ops
https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/resource-based-constrained-delegation
https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4741
https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769
https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/3bff5864-8135-400e-bdd9-33b552051d94
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9f44-e1453be7af5a
