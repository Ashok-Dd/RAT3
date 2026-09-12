package com.example.rat3.scanner

import android.content.Context

/**
 * The user's own "I trust this app, stop scanning it" choices — separate from
 * [AppTrustEngine]'s automatic Play-Store-baseline trust. A user can mark any app trusted
 * regardless of install source; doing so short-circuits every per-app check for that app
 * (AppOps calls, blocklist hashing, Permission Tracker naming) so RAT3's ongoing work is
 * spent on the untrusted set, not re-verifying apps the user has already vetted themselves.
 *
 * A newly-installed app is never in this set until the user explicitly adds it, so every
 * new install goes through the full evidence ladder by default.
 *
 * Backed by SharedPreferences so it's available synchronously to every scan without a Dart
 * round-trip, and survives app restarts.
 */
object UserTrustStore {
    private const val PREFS = "rat3_user_trust"
    private const val KEY_SET = "trusted_packages"

    fun getTrustedPackages(context: Context): Set<String> {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        // Defensive copy — SharedPreferences docs warn against mutating the returned set.
        return (prefs.getStringSet(KEY_SET, emptySet()) ?: emptySet()).toSet()
    }

    fun setTrusted(context: Context, packageName: String, trusted: Boolean) {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val current = (prefs.getStringSet(KEY_SET, emptySet()) ?: emptySet()).toMutableSet()
        if (trusted) current.add(packageName) else current.remove(packageName)
        prefs.edit().putStringSet(KEY_SET, current).apply()
    }
}
