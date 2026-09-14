# Scanner Tab

## What it's for

This is the "run something right now" tab, and it holds two genuinely different tools
behind a toggle at the top:

- **Device Monitor** — controls and manual triggers for the live, continuous
  post-installation monitoring described throughout this section.
- **Scan an APK** — the entry point into the entirely separate
  [pre-installation scanner](../pre-installation/README.md), for checking a single
  `.apk` file before installing it.

They share a tab purely for convenience; the engines, data, and verdicts behind them are
completely independent (see the [top-level overview](../README.md) for why).

## Device Monitor mode

### The five background layers

A live status list shows all five layers of the continuous monitor and whether each is
currently running:

| Layer | What it watches |
|---|---|
| **Layer 1 — Runtime Monitor** | CPU, memory, running processes, and device root status, re-checked roughly every 15 seconds. |
| **Layer 2 — Network Analyzer** | Per-app data usage deltas and a small suspicious-IP/port heuristic, re-checked roughly every 20 seconds. (The [Network tab](02-network-tab.md)'s opt-in real-time connection monitor is a separate, more detailed engine layered on top of this.) |
| **Layer 3 — Permission Tracker** | Which *other* installed apps are actively using — or have heavy background time while holding — camera, microphone, or background-location access. See its own section below. |
| **Layer 4 — Alert Engine** | Deduplicates and routes every layer's findings into the [Alerts tab](03-alerts-tab.md). |
| **Layer 5 — Risk Engine** | Combines roughly 65 real-device signals into the Dashboard's overall score. See [Risk Scoring Engine](07-risk-scoring-engine.md). |

A master switch turns all five on or off together; turning them off also stops the
background foreground-service notification.

### What actually keeps running once you close the app

This matters enough to be precise about: RAT3 has **two separate scanning engines**, not
one, and only one of them is built to survive the app being fully closed.

- **A native background service** — a small, focused set of checks: is the camera or mic
  genuinely active right now, is any app uploading data in the background, is the device
  rooted, is a sideloaded app holding several risky permissions at once, is an
  accessibility service actually turned on. This is the one built for real persistence:
  it uses two independent timers (one for while the screen is on, one that can wake the
  CPU even during deep sleep), holds a wake lock while scanning, and re-arms itself again
  even if a scan cycle fails — one failed cycle can't silently end the loop. It also
  restarts itself after a reboot. This is what the **auto-scan interval** slider (5 minutes
  to 3 hours, 10 minutes by default) actually controls, and it keeps running whether or not
  you've opened RAT3 recently.
- **The rich Layers 1–5 shown above, and the full Dashboard score** — these run inside the
  app itself, and update immediately when you open the app and roughly once a minute while
  it stays open. They do **not** currently have their own persistent background execution
  the way the native service does; if Android fully stops the app process in the
  background (some manufacturers, including Vivo's, are aggressive about this unless the
  app is whitelisted), the detailed score pauses until you reopen RAT3 — the native layer
  above keeps watching regardless, but it does not evaluate the full evidence ladder or
  the six-category score the Dashboard shows.

**Scan Now** runs an immediate check across all five layers instead of waiting for the
next automatic cycle.

### Sensor Scan

A focused, one-tap check specifically for camera, microphone, and location abuse across
every installed app — the same underlying real-time sensor data the Permission Tracker
uses continuously, surfaced here as an on-demand list you can review at any time rather
than waiting for an alert. The same screen also checks whether screen recording is
currently active and lists background apps holding a capability that can read clipboard
content (input method or accessibility service) — real device-state reads, not permission
tallies, same as the mic/camera checks above them.

### Scan All Apps

A full audit of every installed app, producing a **Trusted / Needs Review / Suspicious /
Malicious Indicators** verdict for each one — this is the feature that replaced an earlier,
broken version that used to flag ordinary apps like WhatsApp or a banking app just for
holding permissions. The full reasoning behind how a verdict is reached is documented
separately: [App Trust Engine](06-app-trust-engine.md).

### Permission Tracker, in more detail

The Permission Tracker specifically names *other* installed apps by capability, using two
tiers of evidence:

- **Actively using it right now** — the app's camera or microphone is genuinely in use at
  this exact moment. For the **microphone specifically**, this is an exact match: Android
  exposes which app owns every live recording session, so a microphone hit here is a
  confirmed fact, not a guess. Camera has no equivalent per-app API on Android, so a camera
  hit is the best available candidate match (permission held + genuinely active right now),
  not a certainty. Either way, "active right now" includes an app whose foreground service is
  still running even after you've closed its screen and locked the phone — not just an app
  with a window open — which is what lets this catch a RAT-style pattern of recording after
  you've stopped actively using the app. This is the strongest, highest-severity signal this
  layer raises.
- **Holds the permission and has heavy background time** — more than two hours of
  background activity while holding camera, microphone, or background-location access.

**Both tiers only fire for an app that is *also* not an established, trusted install** —
sideloaded, from an unknown installer, or installed within the last week — **and not an app
you've explicitly marked trusted yourself** (see the [App Trust Engine](06-app-trust-engine.md)'s
"Trusting an app yourself" section). An ordinary, long-installed, Play-Store app doing
exactly the same things (using its own camera, running in the background) never triggers
this layer, for the same reason nothing else in RAT3 flags a single ordinary signal by itself.

**Example:** a photo-editing app that's been installed for six months and briefly uses the
camera while you're using it → no alert, expected behavior. A "flashlight" app installed
two days ago from outside the Play Store that's been running in the background for three
hours while holding microphone access → an alert naming that specific app, because both
"untrusted install" and "sustained background sensor access" are true at once. The same
app's foreground service quietly recording after you've backgrounded it and locked the
screen → still caught, and still named, because "active right now" doesn't require its
window to be open.

Every alert this layer raises comes with an **Open App Info** action — Android gives no
unrooted app a way to force-stop another app's process or silently revoke its permissions,
so this takes you straight to the one screen where you can do both yourself, in one more tap.

## Scan an APK mode

This mode hosts the entire [pre-installation scanner](../pre-installation/README.md)
inside the same app shell: pick a file, watch the four-layer analysis run, and get a
SAFE/SUSPICIOUS/MALICIOUS verdict — see that section's docs for the full detail.
