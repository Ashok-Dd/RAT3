# Layer 1 — App Safety Analysis

## What it's for

Before looking at a single line of code, an APK's own manifest — the file every Android
app must ship that declares what it wants to do — already tells you a lot. Layer 1 reads
that declaration and asks: **does this app's declared shape look like something that
misbehaves?**

## What it actually looks at

| Signal | What it means | Example finding |
|---|---|---|
| **Dangerous permissions** | Permissions Android itself classifies as sensitive (contacts, SMS, camera, microphone, location, call log, etc.) | "Dangerous permission: RECORD_AUDIO" |
| **Suspicious permissions** | Permissions that are legal but rarely needed and frequently abused by RAT/spyware (draw-over-other-apps, modify system settings, install packages, bind to an accessibility service, kill background processes) | "Rarely-legitimate permission: SYSTEM_ALERT_WINDOW" |
| **Declares an unusually large permission set** | More than 30 permissions total | "Declares 34 permissions — unusually large set" |
| **Exported components** | Activities/services/receivers other apps can invoke directly, beyond the handful every normal app has | "12 exported components — more than typical" |
| **Old target SDK** | Targeting a very old Android version deliberately sidesteps modern runtime-permission and background-execution restrictions | "Targets very old API 19 (pre-runtime-permissions)" |
| **Accessibility-service abuse** | Declares an accessibility service that can read every app's on-screen content and/or simulate taps and swipes — the single most common capability behind banking trojans | "Accessibility service can read on-screen content of every app — a common keylogging/overlay technique" |
| **Accessibility + persistence combo** | Accessibility abuse *combined with* an overlay permission or boot-persistence — the classic RAT/banking-trojan fingerprint | "Accessibility abuse combined with overlay/boot-persistence — strong RAT indicator" |
| **Device Administrator receiver** | Can enforce lock/wipe policies and resist normal uninstallation | "Declares a Device Administrator receiver" |

## How it turns this into a score

Nothing here is instant-malicious. Each signal contributes a bounded number of points
(so no single permission can dominate the layer's score by itself), and the points are
capped per category:

- Dangerous permissions: a few points each, capped well below the danger line even if an
  app has a lot of them.
- Suspicious permissions: a larger point value each, also capped.
- Exported components: only counted **beyond** the number a normal app typically has —
  the first several are free.
- Old target SDK: a fixed penalty depending on how old.
- Accessibility abuse: the largest single contributor in this layer, because it is the
  single strongest real-world signal a layer working from the manifest alone can see.

The layer's final number for this pass is capped at 100 and handed to the
[Decision Engine](05-final-verdict-engine.md), which weighs it against the other three
layers — Layer 1 is **never** the sole reason an app is marked MALICIOUS.

## Worked example

**A flashlight app that asks for:** camera (for the flash), storage, and network access.

- Camera and storage are dangerous permissions → a few points.
- No suspicious permissions, no accessibility service, no device admin, normal number of
  exported components, modern target SDK.
- **Result:** a low score, no accessibility or persistence findings — reads as routine.

**A "cleaner" app that asks for:** an accessibility service ("to close background apps for
you"), draw-over-other-apps, and declares a boot-completed receiver.

- Accessibility service that can read screen content → the largest point contribution in
  this layer.
- Overlay permission + boot-persistence + accessibility together → the combo finding fires,
  adding more on top.
- **Result:** a high Layer 1 score with an explicit finding calling out the exact
  combination — this is precisely the shape of a real banking trojan (SpyNote, Cerberus,
  Anubis-family malware all use this pattern), regardless of what the app claims to do.

## Why it's built this way

A cleaning app that legitimately needs an accessibility service is rare but does exist.
That's why this layer never treats accessibility access alone as an instant verdict — it's
weighted heavily, but it's one signal among several that the
[Decision Engine](05-final-verdict-engine.md) combines with the other three layers before
reaching MALICIOUS.
