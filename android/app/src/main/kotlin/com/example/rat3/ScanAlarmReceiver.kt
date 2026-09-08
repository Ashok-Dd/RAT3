package com.example.rat3

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log

/**
 * ScanAlarmReceiver
 *
 * Receives the alarm fired by AlarmManager.setExactAndAllowWhileIdle().
 * This broadcast fires even during Doze mode — which is exactly what we need.
 *
 * WHY a separate receiver instead of waking the service directly:
 *   AlarmManager fires a BroadcastReceiver reliably during Doze.
 *   It cannot start a Service directly in a Doze-safe way.
 *   So: Alarm → BroadcastReceiver (acquires WakeLock) → starts Service.
 *
 * WakeLock MUST be acquired here, BEFORE starting the service.
 * If we acquire it inside the service's onStartCommand(), the CPU
 * can fall asleep in the gap between onReceive() ending and
 * onStartCommand() being called — causing a missed scan.
 *
 * The static WakeLock in ScanForegroundService bridges this gap.
 * It is acquired here and released at the end of the scan inside
 * the service, giving us an unbroken CPU-awake window.
 */
class ScanAlarmReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "RAT-AlarmReceiver"
    }

    override fun onReceive(context: Context, intent: Intent) {
        Log.i(TAG, "Alarm received — action=${intent.action}")

        // Step 1: Acquire WakeLock IMMEDIATELY — before anything else.
        // This keeps the CPU awake through the entire chain:
        //   onReceive() → startForegroundService() → onStartCommand() → scan
        ScanForegroundService.acquireStaticWakeLock(context)

        // Step 2: Start the foreground service to run the actual scan.
        // Recover the persisted scan interval from shared prefs.
        val intervalMs = context.getSharedPreferences("rat_scan_prefs", Context.MODE_PRIVATE)
            .getLong(ScanForegroundService.KEY_INTERVAL, ScanForegroundService.DEFAULT_INTERVAL_MS)

        val serviceIntent = Intent(context, ScanForegroundService::class.java).apply {
            action = ScanForegroundService.ACTION_RUN_SCAN
            putExtra(ScanForegroundService.EXTRA_INTERVAL_MS, intervalMs)
        }

        // Must use startForegroundService on Android 8+ for background service starts
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(serviceIntent)
        } else {
            context.startService(serviceIntent)
        }

        Log.i(TAG, "ScanForegroundService started from alarm — interval=${intervalMs/60000}min")
    }
}