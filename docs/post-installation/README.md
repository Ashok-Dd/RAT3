# Post-Installation Monitor

## What it's for

Once an app is actually installed and running, a completely different kind of question
becomes possible: not "does this file look dangerous on paper?" but **"is anything on
this device actually behaving like a RAT or spyware right now?"** — reading a microphone
at 3 AM, sending data the moment the camera turns on, a sideloaded app quietly gaining
control of the screen, an unexplained connection repeating every few seconds to the same
address.

This half of RAT3 runs continuously in the background (a persistent Android foreground
service, visible as a permanent notification) and re-checks the device on a timer even
if you never open the app.

## The five tabs, at a glance

| Tab | Answers the question | Docs |
|---|---|---|
| **Dashboard** | "Overall, how worried should I be about this device right now?" | [Dashboard](01-dashboard.md) |
| **Network** | "Is any app talking to a remote address in a way that looks like exfiltration or a beacon, not just normal internet use?" | [Network tab](02-network-tab.md) |
| **Alerts** | "What has RAT3 actually found, and why?" | [Alerts tab](03-alerts-tab.md) |
| **Scanner** | "Run a check right now" — manual scans, the sensor-abuse check, and the full installed-app audit | [Scanner tab](04-scanner-tab.md) |
| **Settings** | Turn monitoring/notifications on or off, redo permission setup, reset accumulated data | [Settings tab](05-settings-tab.md) |

Two deeper pages cover engines that power several tabs at once rather than living behind
one screen:

- [**App Trust Engine**](06-app-trust-engine.md) — the evidence-based reasoning behind the
  Scanner tab's "Scan All Apps" audit of every installed app.
- [**Risk Scoring Engine**](07-risk-scoring-engine.md) — the rule-based engine behind the
  Dashboard's single overall risk number, and the roughly 65 individual real-device
  signals that feed it.

## The rule every one of these engines follows

This is worth repeating, because it's the entire design philosophy of the post-install
half: **holding a permission, sending some data, or running in the background is never,
on its own, enough to call an app or a connection suspicious.** WhatsApp holds camera,
microphone, contacts, and location permissions, runs in the background, and sends data
constantly — none of that makes it a RAT. What actually matters is *correlation*: does an
**untrusted** app (sideloaded, unknown installer, installed yesterday) **also** hold
control-style capabilities (accessibility service, device admin, draw-over-other-apps) or
have its camera/microphone **actually** active while data is going out? That combination
is what real spyware looks like — and it's what every scoring system in this half of the
app is built to look for, instead of penalizing ordinary apps for existing.

## What the monitor needs from you

During first-run setup (and any time later from **Settings → Fix permissions**), RAT3
asks for:

| Permission | What it unlocks | What's lost if skipped |
|---|---|---|
| **Notifications** | Alerts you the moment something is found | You'd only see findings by opening the app |
| **Usage access** | See which apps run in the background and for how long | Background-abuse detection (Permission Tracker, some Risk Engine signals) goes blind |
| **Ignore battery optimization** | Keeps the background monitor alive when the screen is off | Android may pause monitoring to save battery |
| **Camera / microphone / location** | Lets RAT3 check whether *another* app is actively using these sensors right now | Real-time sensor-abuse detection goes blind |

Any of these can be skipped and granted later — RAT3 will simply see less, and says so,
rather than pretending it still has full visibility.
