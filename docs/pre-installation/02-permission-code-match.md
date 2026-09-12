# Layer 2 — Permission ↔ Function Match

## What it's for

Layer 1 reads *what an app asked for*. Layer 2 asks a different question: **does the
app's actual code look like it uses what it asked for — or does it look like it's holding
permissions it has no real use for (over-privilege), or quietly doing something far more
dangerous that it never declared plainly?**

## What it actually looks at

### 1. Declared-but-unused permissions

For a short list of especially sensitive permissions, Layer 2 checks whether the app's
code contains the specific API calls that permission is normally used for:

| Permission | What the code should contain if it's genuinely used |
|---|---|
| SEND_SMS | Calls to send a text message |
| RECORD_AUDIO | Calls to start a microphone recording session |
| CAMERA | Calls to open the camera hardware |
| READ_CONTACTS | References to the contacts database |
| ACCESS_FINE_LOCATION | Calls to request GPS location updates |
| READ_PHONE_STATE | Calls to read device/SIM identifiers |
| READ_SMS | References to the SMS content provider |
| READ_CALL_LOG | References to the call-log content provider |

If a permission from this list is declared but **none** of its matching code patterns
show up anywhere in the app, that's flagged — deliberately as a **low-confidence** signal,
because libraries, unused feature flags, and reflection-based code can legitimately trigger
a false match here. It's evidence worth weighing, not proof of anything on its own.

### 2. A short list of genuinely dangerous API calls

Independent of any permission, four specific capabilities are flagged wherever they
appear, because there is essentially no ordinary reason a consumer app needs them:

| API | Why it matters |
|---|---|
| `Runtime.exec()` | Executes an arbitrary shell command |
| `DexClassLoader` | Loads and runs additional code at runtime — a classic way to stage a hidden payload after install |
| `ProcessBuilder` | Spawns external processes |
| `ServerSocket` | Opens a listening network port on the device — a possible backdoor |

## How it turns this into a score

- Each declared-but-unused permission adds a modest number of points, capped overall so a
  handful of unused permissions can't push this layer's score high on their own.
- Each dangerous API found adds its own fixed point value, and these **do** stack — an app
  using two or three of these together scores meaningfully higher than one using none.
- If the app's code was too large to scan completely (very large multi-dex apps), that's
  noted as an informational finding, not treated as suspicious in itself.

## Worked example

**A messaging app** declares RECORD_AUDIO (for voice messages) and the code contains
audio-recording API calls, plus SEND_SMS with matching SMS-sending code (for an
"invite a friend" feature). No dangerous APIs anywhere in the code.
→ No mismatch findings, no dangerous-API findings. Clean pass through this layer.

**A "battery saver" app** declares READ_CONTACTS and READ_SMS but neither permission has
any matching code pattern anywhere in the app — and separately, the code contains a call
to `DexClassLoader`.
→ Two low-confidence mismatch findings (worth a modest score bump each) **plus** the
dangerous-API finding for dynamic code loading (a much larger score bump on its own). The
combination — permissions with no legitimate use, next to code that loads more code at
runtime — is exactly the shape of a dropper that stages its real payload after the user
already trusts it enough to have it installed.

## Why it's built this way

Permission mismatches are common in perfectly ordinary apps (an SDK bundled in for a
feature that was never finished, a permission requested "just in case"), so they're
weighted lightly and explicitly labeled low-confidence. The dangerous-API list is short
and deliberately conservative — it used to include reflection helpers (`PathClassLoader`,
bare `Method.invoke`) that show up in essentially every modern app through Kotlin and
AndroidX internals, which only produced noise; those were removed so what's left actually
means something when it fires.
