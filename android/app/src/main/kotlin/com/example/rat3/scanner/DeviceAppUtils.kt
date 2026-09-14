package com.example.rat3.scanner

import android.content.Context
import android.content.pm.PackageInfo
import android.util.Log

/**
 * Small device/app heuristics shared between [com.example.rat3.MainActivity] (foreground,
 * user-triggered scans) and [com.example.rat3.ScanForegroundService] (background, periodic
 * scans) -- deliberately kept in one place because these two scanners used to carry
 * independent copies of similar logic that drifted out of sync: the background service kept
 * flagging things (USB debugging alone, OEM-bundled apps misread as "sideloaded", an
 * accessibility service merely DECLARED rather than actually enabled) that the foreground
 * scanner had already stopped treating as risk signals. A single shared implementation can't
 * drift from itself.
 */
object DeviceAppUtils {
    private const val TAG = "RAT3-DeviceAppUtils"

    // Apps installed within this window of the device's earliest-installed package are
    // treated as factory/carrier preloaded, not user-installed -- see isOemPreinstalled.
    const val OEM_PRELOAD_WINDOW_MS = 72 * 60 * 60 * 1000L

    /**
     * Approximates "installed by the user" vs "came preloaded with the phone" -- Android has
     * no direct flag for this on non-system-partition OEM/carrier apps (only true /system
     * apps get FLAG_SYSTEM; a great many manufacturer/carrier apps ship as ordinary non-system
     * packages that are still factory-installed, never downloaded by the user).
     *
     * Every app flashed as part of the original device image gets (almost) the exact same
     * firstInstallTime, clustered at first boot. Anything installed afterward -- even the
     * same day the phone arrives -- gets a firstInstallTime that's meaningfully later. So:
     * find the earliest firstInstallTime across every installed package on the device, and
     * treat anything within a generous window of that as "came with the phone."
     */
    fun computeDeviceSetupTimeMs(packages: List<PackageInfo>): Long =
        packages.minOfOrNull { it.firstInstallTime } ?: 0L

    fun isOemPreinstalled(pkg: PackageInfo, deviceSetupTimeMs: Long): Boolean =
        pkg.firstInstallTime - deviceSetupTimeMs <= OEM_PRELOAD_WINDOW_MS

    /** Package names with a currently-ENABLED (not just declared/requested) accessibility
     *  service -- holding the BIND_ACCESSIBILITY_SERVICE permission in a manifest only means
     *  an app CAN offer one; plenty of legitimate apps (password managers, screen readers)
     *  declare the capability without the user ever turning it on. */
    fun getActiveAccessibilityServicePackages(context: Context): Set<String> {
        return try {
            val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE)
                as android.view.accessibility.AccessibilityManager
            am.getEnabledAccessibilityServiceList(
                android.accessibilityservice.AccessibilityServiceInfo.FEEDBACK_ALL_MASK,
            )
                .mapNotNull { it.resolveInfo?.serviceInfo?.packageName }
                .toSet()
        } catch (e: Exception) {
            Log.w(TAG, "getActiveAccessibilityServicePackages failed: ${e.message}")
            emptySet()
        }
    }
}
