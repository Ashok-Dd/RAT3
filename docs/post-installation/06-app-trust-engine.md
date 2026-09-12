# App Trust Engine (Scan All Apps)

## What it's for

This is the reasoning behind the [Scanner tab](04-scanner-tab.md)'s "Scan All Apps"
feature — auditing every installed app and deciding, for each one, how much attention it
deserves. It exists specifically to answer one narrow, important question honestly:

> **Does this app show real evidence of RAT-like behavior — not just "it has a lot of
> permissions" or "it uses the network"?**

## The problem this replaced

An earlier version of this feature scored apps by adding points for holding permissions
and doing ordinary things — enough camera/microphone/location/contacts permissions, or
running in the background, or sending any data at all, was enough to push an app past the
"malicious" line. In practice this meant messaging apps, payment apps, and streaming apps
— exactly the apps that legitimately need lots of permissions and run constantly — got
flagged as dangerous simply for existing and working normally. That approach was replaced
entirely with the evidence ladder below.

## The trust baseline: most apps should never reach this far

Before looking at any specific evidence, one check runs first: is this app **installed
from the Play Store**, **not installed in just the last week**, and **not** holding the
specific combination of accessibility service + (draw-over-other-apps, or device-admin
rights, or auto-start-on-boot)?

If all of that is true, the app is marked **TRUSTED** immediately — full stop, regardless
of how many permissions it holds, how much data it sends, or how long it runs in the
background. This one check is what keeps WhatsApp, a banking app, YouTube, or any other
ordinary, established app from ever being flagged, no matter what it legitimately does.

## For everything else: an evidence ladder, not a single score

Apps that don't clear the trust baseline (sideloaded, from an unknown source, installed
very recently, or holding that specific capability combination) get evaluated against
four tiers of evidence. **Higher tiers require more, not less, to trigger — and it always
takes a combination, never a single fact alone**, except for a confirmed match.

| Tier | Examples of evidence at this tier | What it takes to move up a verdict level |
|---|---|---|
| **Weak** | Sideloaded / unknown install source, installed within the last 7 days, targets a very old Android version | Never escalates alone — takes **two or more** together |
| **Medium** (Private Data Access) | Can read SMS messages, can read notifications (including message/email previews), accessibility can read on-screen content, tracks background location | **One** is enough to flag for review; **two or more** together escalate further |
| **Strong** | Accessibility service combined with overlay/device-admin/auto-start, real active camera/microphone use right now, can draw over other apps *and* read the screen, holds Device Administrator rights | **One** is enough to flag as suspicious; **two or more** together reach the top tier |
| **Confirmed** | The installed app's file matches a known-malicious file hash (the same blocklist the [pre-installation scanner](../pre-installation/03-signature-reputation-check.md) uses) | Reaches the top tier **on its own** — this is the one case where a single fact is enough, because it isn't a guess |

## The four verdicts

| Verdict | Meaning |
|---|---|
| **TRUSTED** | Cleared the baseline, or found genuinely nothing concerning. |
| **UNKNOWN** | Not from the Play Store, but no other notable evidence — informational, not alarming. |
| **NEEDS REVIEW** | Enough weak/medium evidence to be worth a look. |
| **SUSPICIOUS** | At least one strong signal, or two medium signals. |
| **MALICIOUS INDICATORS** | Two or more strong signals, or a confirmed file-hash match. |

## Private Data Access is always shown — even for trusted apps

Whether an app can read your SMS, read your notifications, or (via an accessibility
service) read anything on screen is tracked and shown **regardless of trust level** — the
difference is only in tone and consequence. A trusted app's capability shows up as plain,
calm, informational context ("PhonePe can read SMS — used for OTP verification, a common
and expected capability for payment apps"). The same capability on an untrusted app
becomes actual evidence contributing to that app's verdict. Nothing is hidden either way;
only the framing changes to match how concerning it actually is.

## Worked examples

**WhatsApp, PhonePe, Google Pay, YouTube** — all Play-Store installed, all long-established,
none holding the accessibility+overlay/admin/auto-start combination. → **TRUSTED** for all
four, regardless of their large permission lists, constant background activity, or how
much data they send. (This is the exact scenario that motivated rebuilding this engine.)

**A sideloaded "cleaner" app with an accessibility service and draw-over-other-apps
permission.** Two strong signals fire together (the accessibility+overlay combo counts as
evidence in more than one way at once — see the technical note below). → **MALICIOUS
INDICATORS**, with the evidence list explicitly naming the accessibility+overlay
combination as "a classic RAT/banking-trojan pattern."

**An app installed three days ago from outside the Play Store that can read SMS
messages**, nothing else notable. One medium-tier signal on an untrusted app. →
**NEEDS REVIEW**, with the specific reason ("Can read your SMS messages") shown plainly.

**An app installed from outside the Play Store, established for over a year, with
nothing else notable about it.** Not trusted by the baseline (not Play Store), but zero
weak/medium/strong evidence beyond that one fact. → **UNKNOWN** — flagged as
not-fully-vetted, but explicitly not treated as suspicious for that alone.

**A sideloaded app with its camera genuinely active right now** (checked via the same
real-time hardware state Android itself tracks, not just "it holds the permission"). One
strong signal on an untrusted app. → **SUSPICIOUS.**

## Technical note on the "why two signals from one fact" example above

Accessibility-service abuse combined with an overlay permission is specifically flagged in
two related but distinct ways: once as "the classic persistence/control combo" and once as
"can draw over other apps *and* read the screen" — because these describe two genuinely
different attack capabilities (staying resident vs. actively controlling what you see and
tap) that happen to share the same two underlying permissions. This is a deliberate
design choice, not double-counting by accident: this exact combination (accessibility +
overlay, on a sideloaded app) matches real-world malware families like SpyNote, Cerberus,
and Anubis closely enough that reaching the top verdict from it alone — without needing an
unrelated third signal — is the intended, correct behavior.

## Honesty notes

- **The confirmed-match check only runs for apps that already failed the trust baseline** —
  hashing every installed app's file on every scan would be slow and pointless for apps
  already known to be trustworthy.
- **The blocklist itself ships with placeholder entries**, same caveat as the
  pre-installation scanner's — the mechanism is real and correct; the data behind it would
  need a real threat-intelligence source in a production deployment.
