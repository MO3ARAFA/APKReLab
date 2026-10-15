# From audit to payment: the sales loop (Phase 8)

The agency finds and audits prospects, writes validated outreach, and now also prices the work, drafts the replies, reminds you to follow up and tracks every lead. **It never sends anything and never touches your money.** You send the messages and you confirm the payments; the agency prepares everything else.

## The loop

1. A cycle audits prospects and the COO offers the batch ("Release to me?"). On **Release** each message arrives in your Telegram with:
   - a public contact path found on the company's own site (role addresses such as `info@`/`sales@`, or the contact-form URL; role addresses only, never guessed and never personal ones),
   - a suggested subject, the greeting (with a warning when the name is unverified),
   - your legal footer: postal address and an opt-out line (`SENDER_ADDRESS`),
   - for non-English sites, an **AI translation** (unverified: have a native speaker check it) when a model is available within the caps.
2. You send it from your own email. Then: `/sent all` (or `/sent Acme`). A follow-up draft is scheduled after 3 days of silence and a last one 4 days later. Never more than two.
3. When someone answers: `/replied Acme`. You get the **reply kit**: the audit's top findings, a price, the contact, and a ready draft with PayPal links.
4. After they pay, check your PayPal, then `/won Acme 149` and confirm. The revenue is logged against PRJ-03, the lead becomes `won`, and the first Group A revenue unlocks the reserve vault.
5. Deliver with `/report Acme`: the written report (saved to `output/PRJ-03/clients/`), built from the stored findings with a fix recipe for each. Review it before sending.

Other commands: `/leads`, `/quote Acme 120` (your own price), `/lost Acme`, `/optout Acme` (permanent do-not-contact), `/addlead https://site.com Company` (queue a prospect you found yourself; max 10 waiting).

## Pricing (set by the COO, overridable by you)

- **Report only:** `PRICE_REPORT_USD` (default $49): the full written report with a fix recipe for every finding.
- **Report + fixes:** the report price plus the estimated hours for the top 5 fixes times `PRICE_HOURLY_USD` (default $30/h), rounded to $5. The hours come from a fixed table per finding type (for example 2 h for a slow server, 15 min for a meta description) plus 0.5 h for very heavy pages. Above `PRICE_CAP_USD` ($600) the job is flagged **custom**: talk first, no link.
- It is a transparent estimate from one automated homepage check, not a promise. Change any price with `/quote Acme 120`. Doing the fixes is your work (with whatever AI help you use) once the client gives you access.

## Payment: PayPal

Set `PAYPAL_ME=paypal.me/yourname` in `.env`. Links are built as `https://paypal.me/yourname/149USD`. **Open one link yourself first** to check it shows the right amount and your name. Only a plain handle is accepted; anything else is ignored and the draft says the link is missing. Check in PayPal that your account type can receive payments for services in your country, and expect PayPal to hold or review the first payments on a new account. The handle is public, not a secret, but it is kept in `.env`, not in the code.

## Compliance and markets (your responsibility)

Cold commercial email is regulated: CAN-SPAM (US) needs a truthful sender, a postal address and a working opt-out; GDPR/ePrivacy (EU/UK) is stricter and may require a legitimate-interest basis, and some countries restrict unsolicited commercial email altogether. The agency lists only role addresses published on the company's own site, adds the footer and honours `/optout`, but it cannot decide what is lawful where you and the recipient are. When in doubt use the site's contact form or a LinkedIn message, and never contact someone who said no.

## Honest limits

- There is no guarantee of replies or sales. Cold outreach to well-run companies converts rarely; the funnel in your briefings tells you your real numbers.
- Contact discovery reads at most four public pages per company and often finds nothing.
- AI translations can be wrong. The message is the validated English one; the translation is a convenience.
- Quotes assume the homepage is representative. Check the site yourself before you commit to a price.
