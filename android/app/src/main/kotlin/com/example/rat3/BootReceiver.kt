package com.example.rat3

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log

/**
 * Restores monitoring after a reboot (AlarmManager alarms do not survive a reboot).
 *
 * Fires on BOOT_COMPLETED / QUICKBOOT_POWERON (needs RECEIVE_BOOT_COMPLETED).
 *
 * Android 14+ forbids starting most foreground-service types directly from a
 * BOOT_COMPLETED context, so we only **re-arm the AlarmManager alarm** here. When
 * that alarm fires, [ScanAlarmReceiver] starts the service (alarm broadcasts get
 * a temporary exemption). On older Android we start the service straight away.
 */
class BootReceiver : BroadcastReceiver() {

    private companion object {
        const val TAG = "RAT3.BootReceiver"
    }

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        if (action != Intent.ACTION_BOOT_COMPLETED &&
            action != "android.intent.action.QUICKBOOT_POWERON"
        ) {
            return
        }

        val intervalMs = context
            .getSharedPreferences("rat_scan_prefs", Context.MODE_PRIVATE)
            .getLong(ScanForegroundService.KEY_INTERVAL, ScanForegroundService.DEFAULT_INTERVAL_MS)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            // Android 14+: schedule an alarm; ScanAlarmReceiver promotes to FGS when it fires.
            ScanForegroundService.scheduleNextAlarm(context, intervalMs)
            Log.i(TAG, "Boot: alarm re-armed for ${intervalMs / 60000}min (FGS starts on next alarm)")
            return
        }

        ScanForegroundService.acquireStaticWakeLock(context)
        val svc = Intent(context, ScanForegroundService::class.java)
            .putExtra(ScanForegroundService.EXTRA_INTERVAL_MS, intervalMs)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(svc)
        } else {
            context.startService(svc)
        }
        Log.i(TAG, "Boot: service started, interval=${intervalMs / 60000}min")
    }
}
