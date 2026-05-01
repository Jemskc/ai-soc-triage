export const MOCK_EMAIL_STRINGS = [

`From: security-noreply@paypa1-support.xyz
To: jsmith@company.com
Subject: Urgent: Your PayPal account has been limited
Date: Fri, 25 Apr 2026 09:14:02 +0000
Reply-To: collect@harvester-domain.ru
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Received: from mail.paypa1-support.xyz ([185.220.101.45]) by mx.company.com
Authentication-Results: mx.company.com;
  spf=fail smtp.mailfrom=paypa1-support.xyz;
  dkim=fail header.i=@paypa1-support.xyz;
  dmarc=fail p=none header.from=paypa1-support.xyz

Dear Customer,

Your PayPal account has been temporarily limited due to unusual activity.

To restore full access, please verify your account immediately:
https://secure-account-verify.paypa1-support.xyz/login?token=abc123
https://bit.ly/pp-verify2026

Failure to verify within 24 hours will result in permanent account suspension.

PayPal Security Team`,

`From: it-helpdesk@company-internal.net
To: mjones@company.com
Subject: RE: Your password expires in 24 hours - ACTION REQUIRED
Date: Fri, 25 Apr 2026 10:32:17 +0000
Reply-To: phish@attacker-smtp.ru
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Received: from compromised-relay.attacker-smtp.ru ([91.198.174.192]) by mx.company.com
Authentication-Results: mx.company.com;
  spf=fail smtp.mailfrom=company-internal.net;
  dkim=fail header.i=@company-internal.net;
  dmarc=fail p=reject header.from=company-internal.net

Hi Mike,

This is a reminder from the IT Help Desk that your corporate password expires in 24 hours.

Please update it immediately using the self-service portal:
https://login.company-internal.net.attacker.xyz/portal/update-password
https://secure.account-update.xyz/corporate/reset

If you do not update your password, you will lose access to all company systems.

IT Help Desk`,

`From: hr-payroll@company-corp.com
To: finance@company.com
Subject: Q1 Bonus Calculation - Please review attachment
Date: Fri, 25 Apr 2026 11:05:44 +0000
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="---=_Part_1234"
Received: from mail.company-corp.com ([203.0.113.22]) by mx.company.com
Authentication-Results: mx.company.com;
  spf=fail smtp.mailfrom=company-corp.com;
  dkim=pass header.i=@company-corp.com;
  dmarc=fail p=none header.from=company-corp.com

-------=_Part_1234
Content-Type: text/plain; charset=UTF-8

Please find attached the Q1 2026 bonus calculations for your review.
Open the spreadsheet and enable macros to view the full breakdown.

HR Payroll Team

-------=_Part_1234
Content-Type: application/octet-stream; name="Q1_Bonus_2026.pdf.exe"
Content-Disposition: attachment; filename="Q1_Bonus_2026.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAA...
-------=_Part_1234--`,

`From: newsletter@trusted-vendor.com
To: team@company.com
Subject: Your Weekly Security Digest - April 25, 2026
Date: Fri, 25 Apr 2026 08:00:00 +0000
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8
Received: from mail.trusted-vendor.com ([198.51.100.25]) by mx.company.com
Authentication-Results: mx.company.com;
  spf=pass smtp.mailfrom=trusted-vendor.com;
  dkim=pass header.i=@trusted-vendor.com;
  dmarc=pass policy=reject header.from=trusted-vendor.com

<html><body>
<h1>Weekly Security Digest</h1>
<p>This week's top threat intelligence from Trusted Vendor Inc.</p>
<a href="https://www.trusted-vendor.com/digest/2026-04-25">Read Full Report</a>
<a href="https://www.trusted-vendor.com/unsubscribe">Unsubscribe</a>
<img src="https://track.trusted-vendor.com/pixel/open?id=abc123" width="1" height="1">
</body></html>`,

`From: cfo@company.com.biz
To: accounts-payable@company.com
Subject: Urgent wire transfer needed - confidential
Date: Fri, 25 Apr 2026 14:22:00 +0000
Reply-To: real-cfo-personal@gmail.com
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Received: from mail.company.com.biz ([45.142.212.100]) by mx.company.com
Authentication-Results: mx.company.com;
  spf=fail smtp.mailfrom=company.com.biz;
  dkim=none;
  dmarc=fail p=none header.from=company.com.biz

Hi,

I need you to process an urgent wire transfer of $87,500 to a new vendor.
This is time-sensitive and must be completed today.

Please do not discuss this with anyone until the transfer is complete.
Reply directly to this email with confirmation.

Best,
Robert Chen
CFO, Company Inc.`,

`From: offers@shoppingdeals-weekly.com
To: bwilliams@company.com
Subject: [NEWSLETTER] Exclusive deals this week + 50 special offers inside!
Date: Thu, 24 Apr 2026 18:00:00 +0000
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8
Received: from mail.shoppingdeals-weekly.com ([198.51.100.88]) by mx.company.com
Authentication-Results: mx.company.com;
  spf=pass smtp.mailfrom=shoppingdeals-weekly.com;
  dkim=none;
  dmarc=none header.from=shoppingdeals-weekly.com

<html><body>
<h2>This week's hottest deals!</h2>
<a href="https://track.shoppingdeals-weekly.com/r?id=1&url=https://amazon.com/deal1">Deal 1</a>
<a href="https://track.shoppingdeals-weekly.com/r?id=2&url=https://ebay.com/deal2">Deal 2</a>
<a href="https://bit.ly/deals-apr26-1">Flash Sale</a>
<a href="https://tinyurl.com/deals26">Limited Offer</a>
<a href="https://shoppingdeals-weekly.com/unsubscribe">Unsubscribe</a>
<img src="https://track.shoppingdeals-weekly.com/pixel?uid=bwilliams" width="1" height="1">
</body></html>`,

`From: support@microsoft-account.verify-login.xyz
To: rthomas@company.com
Subject: Sign-in attempt blocked - verify your identity now
Date: Fri, 25 Apr 2026 07:44:31 +0000
Reply-To: noreply@microsoft-account.verify-login.xyz
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Received: from smtp.verify-login.xyz ([178.73.215.171]) by mx.company.com
Authentication-Results: mx.company.com;
  spf=fail smtp.mailfrom=verify-login.xyz;
  dkim=fail header.i=@verify-login.xyz;
  dmarc=fail p=none header.from=verify-login.xyz

Microsoft Account Team

A sign-in to your Microsoft account was blocked from an unrecognized device.

Location: Moscow, Russia
Device: Windows 10

If this was you, click here to allow: https://login.microsoftonline.com.verify-login.xyz/allow?token=xyz789

If this was NOT you, secure your account immediately:
https://account.microsoft.com.secure-update.xyz/recover
https://bit.ly/ms-secure-2026

Your account will be locked in 2 hours if no action is taken.`,

`From: alice.chen@company.com
To: team-engineering@company.com
Subject: Engineering team standup notes - April 25
Date: Fri, 25 Apr 2026 09:00:00 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Received: from mail.company.com ([10.0.1.20]) by mx.company.com
Authentication-Results: mx.company.com;
  spf=pass smtp.mailfrom=company.com;
  dkim=pass header.i=@company.com;
  dmarc=pass policy=reject header.from=company.com

Hi team,

Here are the notes from this morning's standup:

- Sprint 12 velocity: on track
- Deployment scheduled for Monday 9 AM
- Blocker: waiting on legal sign-off for new auth flow

Please update your Jira tickets before EOD.

Thanks,
Alice`,

];
