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
| **Layer 5 — Risk Engine** | Combines roughly 65 real-device signals into the Dashboard's overall score, roughly once a minute. See [Risk Scoring Engine](07-risk-scoring-engine.md). |

A master switch turns all five on or off together; turning them off also stops the
background foreground-service notification.

### Manual scan and auto-scan interval

**Scan Now** runs an immediate check across all five layers instead of waiting for the
next automatic cycle. The **auto-scan interval** slider controls how often that automatic
cycle repeats on its own — anywhere from every 5 minutes to every 3 hours (10 minutes by
default) — and this keeps happening even if you've closed the app, because the monitor
runs as a genuine background service, not just "while the app is open."

### Sensor Scan

A focused, one-tap check specifically for camera, microphone, and location abuse across
every installed app — the same underlying real-time sensor data the Permission Tracker
uses continuously, surfaced here as an on-demand list you can review at any time rather
than waiting for an alert.

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
  this exact moment (checked via the same real-time sensor state Android itself tracks,
  not just "does it have the permission"). This is the strongest, highest-severity signal
  this layer raises.
- **Holds the permission and has heavy background time** — more than two hours of
  background activity while holding camera, microphone, or background-location access.

**Both tiers only fire for an app that is *also* not an established, trusted install** —
sideloaded, from an unknown installer, or installed within the last week. An ordinary,
long-installed, Play-Store app doing exactly the same things (using its own camera,
running in the background) never triggers this layer, for the same reason nothing else in
RAT3 flags a single ordinary signal by itself.

**Example:** a photo-editing app that's been installed for six months and briefly uses the
camera while you're using it → no alert, expected behavior. A "flashlight" app installed
two days ago from outside the Play Store that's been running in the background for three
hours while holding microphone access → an alert naming that specific app, because both
"untrusted install" and "sustained background sensor access" are true at once.

## Scan an APK mode

This mode hosts the entire [pre-installation scanner](../pre-installation/README.md)
inside the same app shell: pick a file, watch the four-layer analysis run, and get a
SAFE/SUSPICIOUS/MALICIOUS verdict — see that section's docs for the full detail.
