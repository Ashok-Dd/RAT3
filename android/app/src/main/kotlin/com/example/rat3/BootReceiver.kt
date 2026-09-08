package com.example.rat3

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log

/**
 * BootReceiver
 *
 * Fires on BOOT_COMPLETED and QUICKBOOT_POWERON (HTC/Samsung fast boot).
 *
 * After a reboot, ALL AlarmManager alarms are wiped — they do NOT
 * persist across reboots. This receiver re-establishes monitoring by
 * starting ScanForegroundService immediately after boot. The service
 * runs a scan and re-arms the repeating alarm for all future scans.
 *
 * Result: monitoring resumes automatically after every reboot, even
 * if the user never opens the app.
 *
 * Requires: android.permission.RECEIVE_BOOT_COMPLETED
 */
class BootReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "RAT-BootReceiver"
    }

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        if (action != Intent.ACTION_BOOT_COMPLETED &&
            action != "android.intent.action.QUICKBOOT_POWERON") return

        Log.i(TAG, "Boot completed — restoring scan service")

        // Recover persisted interval
        val intervalMs = context
            .getSharedPreferences("rat_scan_prefs", Context.MODE_PRIVATE)
            .getLong(ScanForegroundService.KEY_INTERVAL,
                     ScanForegroundService.DEFAULT_INTERVAL_MS)

        // Acquire WakeLock before starting service (bridges receiver→service gap)
        ScanForegroundService.acquireStaticWakeLock(context)

        val si = Intent(context, ScanForegroundService::class.java).apply {
            putExtra(ScanForegroundService.EXTRA_INTERVAL_MS, intervalMs)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(si)
        } else {
            context.startService(si)
        }

        Log.i(TAG, "Service started after boot — interval=${intervalMs/60000}min")
    }
}