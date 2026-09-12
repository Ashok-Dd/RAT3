package com.example.rat3.scanner

/**
 * All tunable scoring constants for the four analysis layers and the decision engine.
 *
 * Every value is centralised here (instead of being scattered as magic numbers) so the
 * scanner can be calibrated in one place. Each constant carries a one-line rationale.
 *
 * Layer risk scores are clamped to 0..100 by [buildLayerJson]. The decision engine fuses
 * them with the weights in [Decision].
 */
object ScannerConfig {

    /** Hard caps on how much raw APK content is read into memory (prevents OOM on multidex apps). */
    object Limits {
        const val DEX_TEXT_MAX_BYTES = 16 * 1024 * 1024        // 16 MB of concatenated classes*.dex
        const val RESOURCE_TEXT_MAX_BYTES = 8 * 1024 * 1024    // 8 MB of text resources/assets
        const val RESOURCE_TEXT_MAX_ENTRIES = 40               // at most N text entries scanned
        const val ACCESSIBILITY_XML_MAX_BYTES = 512 * 1024
    }

    object Layer1 {
        const val DANGEROUS_PERM_POINTS = 3                    // per dangerous permission
        const val DANGEROUS_PERM_CAP = 24
        const val SUSPICIOUS_PERM_POINTS = 8                   // per suspicious permission
        const val SUSPICIOUS_PERM_CAP = 24

        const val EXPORTED_FREE_ALLOWANCE = 6                  // legit apps commonly export a few
        const val EXPORTED_POINTS_PER_EXTRA = 2
        const val EXPORTED_CAP = 12

        const val TARGET_SDK_VERY_OLD = 23                     // pre-runtime-permissions
        const val TARGET_SDK_VERY_OLD_POINTS = 15
        const val TARGET_SDK_OLD = 28                          // pre-Android 9 background limits
        const val TARGET_SDK_OLD_POINTS = 6
        const val TARGET_SDK_UNKNOWN_POINTS = 4

        const val MANY_PERMISSIONS_THRESHOLD = 30
        const val MANY_PERMISSIONS_POINTS = 8

        const val ACCESSIBILITY_RETRIEVE_CONTENT_POINTS = 20   // can read every screen
        const val ACCESSIBILITY_PERFORM_GESTURES_POINTS = 10   // can tap/swipe for the user
        const val ACCESSIBILITY_PERSISTENCE_COMBO_POINTS = 15  // + overlay or boot-persistence
        const val DEVICE_ADMIN_POINTS = 12
    }

    object Layer2 {
        const val MISMATCH_POINTS = 6                          // per declared-but-unused permission
        const val MISMATCH_CAP = 24

        const val API_RUNTIME_EXEC_POINTS = 14
        const val API_DEX_CLASSLOADER_POINTS = 16
        const val API_PROCESS_BUILDER_POINTS = 12
        const val API_SERVER_SOCKET_POINTS = 10
    }

    object Layer3 {
        const val BLOCKLIST_HIT_POINTS = 100                   // known-bad file hash => malicious
        const val REPACKAGE_MISMATCH_POINTS = 70               // trusted package, wrong signer
        const val DEBUG_SIGNED_POINTS = 8                      // informational, common for sideloads

        const val OBFUSCATION_BASE64_MIN_LEN = 400
        const val OBFUSCATION_BASE64_MIN_COUNT = 8
        const val OBFUSCATION_POINTS = 8

        const val NATIVE_LIB_KNOWN_BAD_POINTS = 30
        const val NATIVE_LIB_WRONG_LOCATION_POINTS = 15       // .so under assets/ or res/

        const val NETWORK_HARDCODED_IP_POINTS = 18
        const val NETWORK_ONION_POINTS = 30
        const val NETWORK_DYNAMIC_DNS_POINTS = 12
        const val NETWORK_DYNAMIC_DNS_CAP = 24
    }

    // Layer 4 is the ML ensemble (scanner/ml/MlModels.kt) — its risk bands (20/40/60/80) and
    // vote threshold (50%) live there, next to the model evaluation code they describe. This
    // object previously held the old heuristic Layer4's constants; removed with that class.

    object Decision {
        const val W1 = 0.20
        const val W2 = 0.20
        const val W3 = 0.35
        const val W4 = 0.25

        const val THRESHOLD_MALICIOUS = 60
        const val THRESHOLD_SUSPICIOUS = 30

        const val ESCALATION_MIN_SCORE = 65                    // forced when Layer 3 has a hard hit
        const val ERRORED_LAYER_MAX_CONTRIBUTION = 15          // an errored layer can't force MALICIOUS

        // A single layer scoring this high is real evidence on its own — the weighted average
        // must never fully launder it away just because the other three layers saw nothing
        // (e.g. a novel/custom RAT with no accessibility abuse and no blocklist match, which
        // Layers 1-3 are structurally blind to, but Layer 4's ML ensemble flagged behaviorally).
        const val SINGLE_LAYER_ALARM_THRESHOLD = 65
        const val SINGLE_LAYER_ALARM_FLOOR = THRESHOLD_SUSPICIOUS
    }
}
