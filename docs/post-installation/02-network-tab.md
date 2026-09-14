# Network Tab

## What it's for

Not "which app used the most data this month" — that's a phone-manager question, and
answering it doesn't tell you anything about compromise. The real question this tab is
built to answer is:

> **Is any process on this device continuously or repeatedly communicating with a
> specific remote address in a way that looks like data exfiltration or a
> command-and-control beacon — not just an app doing its normal job?**

## Two views, because Android limits what's possible without extra setup

### The default view: aggregate data usage (always available)

Without any extra setup, this tab shows each app's total bytes sent and received —
useful supplementary context, but explicitly **not** the main event. A single number like
"WhatsApp: 1.1 GB received" tells you nothing about whether that's normal (it almost
certainly is) or not, which is exactly why this view is labeled as supplementary rather
than being the tab's headline.

### The real thing: Real-Time Connection Monitor (opt-in)

A toggle at the top of the tab turns on genuine **per-connection** visibility: which
process, which remote IP address, which port, which protocol (TCP or UDP), how long the
connection has lasted, and whether it's a one-off request or a repeated/persistent
pattern.

**Why this needs an extra toggle and a system permission prompt:** modern Android
(version 10 and newer) blocks ordinary apps from reading other apps' network connections
directly — there is no permission you can grant that unlocks it. The only way to see real
per-connection detail without rooting the device is for RAT3 to run a small **local VPN**
that the device's traffic passes through, purely to observe it — the connections still go
to their normal, real destinations exactly as if RAT3 weren't there. Turning this on shows
Android's standard "Connection request" system dialog, and a small key icon stays in your
status bar for as long as it's active — this is the normal Android VPN indicator, not
something RAT3 adds.

## How a connection gets judged

Every connection is scored the same evidence-based way as everything else in RAT3 — a
single ordinary connection is **never** flagged, no matter how much data it carries:

| Assessment | When it applies |
|---|---|
| **NORMAL** | The default. Any connection with none of the signals below. |
| **NEEDS INVESTIGATION** | Exactly **one** of the signals below is present. |
| **SUSPICIOUS** | **Two or more** signals present at once. |

The signals that count:

1. **Persistent / repeated communication** — the same app has reconnected to the same
   remote address multiple times, or the connection has lasted more than a couple of
   minutes. (One request to a news site's server is normal; dozens of reconnections to
   the same unfamiliar address in a few minutes looks like a beacon.)
2. **A known suspicious port** — a small set of ports historically associated with
   remote-access tools and backdoors (for example, 1337, 4444, 31337).
3. **A known-malicious IP range** — a short illustrative list of address ranges associated
   with malicious infrastructure (see the honesty note below).
4. **The owning app was already flagged** — if the [Scan All Apps](06-app-trust-engine.md)
   audit already found this specific app suspicious or worse, any connection from it needs
   less additional evidence to be worth a second look.
5. **A DNS query for an algorithmically-generated-looking domain** — when a connection
   *is* a DNS query, its own queried domain name is checked against a conservative
   heuristic (unusual length **and** unusual character entropy, or a long run of
   consonants). This names what *that query itself* was resolving, not a correlation from
   a later connection's IP back to the domain that resolved it — RAT3 does not track that
   link. Deliberately conservative: many legitimate CDN/cloud services also use
   random-looking subdomains, so this is one weak signal among the others here, never
   enough on its own to reach SUSPICIOUS.

## Worked examples

**WhatsApp opens a normal HTTPS connection to a Meta server.** No persistence pattern
worth noting yet, not a suspicious port, not a known-bad range, and WhatsApp isn't
flagged by the App Trust Engine. → **NORMAL.** This is true no matter how much data the
connection carries.

**An unfamiliar "system update" app, already flagged NEEDS REVIEW by Scan All Apps,
repeatedly reconnects to the same unfamiliar IP address every few seconds.** That's two
signals at once — the app's own flag, plus the persistent reconnection pattern. →
**SUSPICIOUS**, with both reasons spelled out in the connection's detail view.

**A connection to a port on the suspicious-ports list, but only once, from a
well-established, Play-Store-installed app.** One signal only (the port). →
**NEEDS INVESTIGATION** — worth a look, not treated as confirmed.

## Honesty notes

- **This is not a general-purpose VPN client.** It exists purely to observe connections
  your device is already making; nothing is rerouted anywhere unusual, and no traffic
  content is inspected — only the connection metadata (who, where, how much, how often).
- **The keeping-your-internet-working part is genuinely hard**, and is documented plainly
  rather than glossed over: making a locally observed connection still work normally
  requires RAT3 to relay it to its real destination itself. This was tested against real
  heavy browsing (multi-resource pages, image-heavy feeds) and works reliably, but it is a
  deliberately simplified implementation built for a monitoring tool, not a
  battle-hardened general VPN product.
- **The suspicious-port and known-bad-IP lists are small, illustrative examples** — the
  same honesty caveat as the pre-installation scanner's blocklist. They demonstrate the
  mechanism; a production deployment would want a real, maintained threat-intelligence
  feed behind them.
- **IPv6 traffic is now relayed and tracked, but unverified on a real device.** The
  packet-level parsing, building, and checksum logic is unit-tested and mirrors the IPv4
  path exactly, but — unlike IPv4, which was tested against real heavy browsing — nobody
  has yet run this build on a device with real IPv6 network traffic. Treat it as
  implemented, not as proven. Packets using IPv6 extension headers (rare outside
  specialized traffic) are not specially handled and will be dropped like any other
  unsupported shape, not misparsed.
