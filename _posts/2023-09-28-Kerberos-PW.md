---
layout: post
title: Not just Kerberoasting
subtitle: Kerberos Tickets and Password Resets
tags: [kerberos]
comments: false
---
**_TLDR_** Kerberos attacks are more then just Golden Tickets and Kerberoasting. Password Resets are not always enough!

## Preface about Kerberos 

Going to keep this part simple and talk about a few key details related to Kerberos authentication you should know. Kerberos Tickets will have a validity period of 10 hours by default in an Active Directory domain. The default renewal period for a Kerberos Ticket is 7 days. 

Kerberos Tickets are commonly used by red teams and real world attackers once they have successfully compromised an account. Understanding the nuance of Kerberos authentications can significantly help defenders and investigators identify an attacker's actions during an incident but also ensure proper remediation steps are performed. The point of this blog is not to minimize other Kerberos-based attacks or other methods of authentication such as pass-the-hash but rather provide a scenario, that may commonly be misunderstood, of what is possible. 

## Compromise Scenario Explained

Consider this scenario, a domain, _swolfsec.corp_, has been compromised and the attackers have gained access to a highly privileged user, _highpriv_user_. With this account, the attacker has full access to the domain controller, and can perform any post compromise attacks they wish (use your imagination). The defenders have identified the compromised account and reset it's password in an effort to thwart the attacker's efforts. Unfortunately, after the password reset, the attacker was still able to misuse the privileged account! How can that be possible!?! 

## Scenario In-Depth 

During this scenario, we will flip between the attacker and defender perspective. There are different ways that this same attack could be achieved but the fundamentals, risks, and opportunities for visibility remain the same. 

First, the attacker uses [Rubeus](https://github.com/GhostPack/Rubeus) to request a Kerberos ticket for the currently compromised user, _highpriv_user_. They are returned a base64 encoded kirbi which is a ticket-granting-ticket or "TGT" that can be used for authentication without the need to supply a password. Many toolsets, such as those from the [impacket](https://github.com/fortra/impacket) collection, allow for the use of a Kerberos ticket rather then a password or a hash.

![tgtdeleg](https://swolfsec.github.io/assets/img/1_tgtdeleg.PNG){: .mx-auto.d-block :}

The Event ID **4769** is a great event log for tracking Kerberos Ticket Requests and it may already be logged because of it's common use in identifying Kerberoasting. In this case, the client address is the compromised workstation (not the attacker system) at IP address _192.168.5.169_ and specifies the _highpriv_user_ account which was compromised. The ticket options presented here are described by Microsoft as _Forwardable, Forwarded, Renewable, Canonicalize, Renewable-ok_ which translates to options of **0x60810010**. This options are not incredibly interesting but the importance  of the Renewable flag will be seen later on. 

![4769](https://swolfsec.github.io/assets/img/2_ticketrequest4769.PNG){: .mx-auto.d-block :} 

The attacker then imports the ticket to their attacker machine which has access to the compromised network. If you notice the time (minutes / seconds) of the 4769 ticket request and the imported ticket they match. Ignore the hours, the test environment has skewed times (not important). In addition, refer back to this screenshot later, as you can see here the valid _starting datetime_, _expiry time_, and _renew until_ time. As we get into renewals, that renewal time will not change but the validity start/expiry will. 

![ticketimport](https://swolfsec.github.io/assets/img/3_ticketimported.PNG){: .mx-auto.d-block :}  

Now they can use the ticket to move laterally, in this case using [smbexec](https://github.com/fortra/impacket/blob/master/examples/smbexec.py) to access the domain controller. Theres many actions an attacker can take at this point but access to the DC is enough to prove our compromise. 

![smbexec1](https://swolfsec.github.io/assets/img/4_smbexec_latmvmt1.PNG){: .mx-auto.d-block :}  

In this scenario, our defenders perform a password reset on the account but **do not** disable the account. 

![resetpw](https://swolfsec.github.io/assets/img/5_resetpw.PNG){: .mx-auto.d-block :}  

Although a password reset was performed, the attacker will still have their ticket imported and notice no changes to it and in fact, using the same method as before to move laterally without needing to provide the new credentials!

![smbexecafterpwrst](https://swolfsec.github.io/assets/img/8_smbexec_latmvmt2_afterpwreset.PNG){: .mx-auto.d-block :}  

As you can imagine, this can result in an endless cat and mouse game where the credentials are reset, the Kerberos ticket is used to request the new credentials and so on. 

The continued use of the Kerberos ticket would not be possible had the defenders also disabled the account. As long as the account is disabled the attacker will be unable to misuse the _highpriv_user_ account. 

![accountdisable](https://swolfsec.github.io/assets/img/9_accountdisable.PNG){: .mx-auto.d-block :}  

With the account disabled, the attacker fails to authenticate even though their ticket is still valid.

![smbexecfail](https://swolfsec.github.io/assets/img/10_failuretosmbexec_accountdisabled.PNG){: .mx-auto.d-block :}  

Unfortunately in our scenario the defenders failed to disable the account. The original ticket will only last 10 hours (by default but can be different depending on your environment), at which point they would need to supply the new password to request a new ticket. 

Although, if the attacker identified that the account had a password reset, they can simply renew the ticket and continue operating within the environment. Remember, by default the renewal of a ticket can occur for 7 days from the date of issue. At the renewal expiry of 7 days, a new ticket would need to be requested. The Event ID **4770** gives descriptive information regarding the user account whose ticket is being renewed, and where the renewal was requested from (in this case _192.168.5.164_ which is the attacker system but in a real scenario this may come from a patient zero system).

![kinitR](https://swolfsec.github.io/assets/img/11_kinit-R.PNG){: .mx-auto.d-block :}  

![ticketrenew4770](https://swolfsec.github.io/assets/img/13_TicketRenewal4770.PNG){: .mx-auto.d-block :}  

The first screenshot above shows the same **renewal** expiry as the original Kerberos Ticket request, but has a new validity start/expiry period. With the renewed ticket and the password reset, a final secretsdump against the Domain Controller shows the attacker's Kerberos Ticket is still valid.  The start/expiry times match the minutes / seconds on the 4770 event log. (klist time - 02:01:55 | Event Log time - 11:01:55)

![secrestdump](https://swolfsec.github.io/assets/img/12_secretsdumpafterrenewal.PNG){: .mx-auto.d-block :}  

Some big caveats here are, during this process the attacker would need to recognize that the password was reset prior to the expiration of the ticket and disabling the account would have prevented further abuse. A common remediation task for Golden Tickets and other kerberos-based attacks involves a [krbtgt double-tap](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password) where the krbtgt account has its password rotated twice with 10 hours between resets. This approach can also be viable for abuse of Kerberos Tickets explained here. The process of performing a double-tap can have significant impact on an organization who relies on Active Directory therefore, it may not be a bad idea to practice performing a krbtgt double-tap prior to an incident. 

While the Kerberos abuse described here may not be as flashy as Golden Tickets or Kerberoasting, its a very real threat and something all defenders should consider. 
