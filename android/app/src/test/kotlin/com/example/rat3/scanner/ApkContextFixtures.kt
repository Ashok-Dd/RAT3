package com.example.rat3.scanner

import java.io.File

/**
 * Builds an [ApkContext] fixture for layer unit tests. All fields default to a "clean app"
 * baseline (no permissions, modern SDK, not debug-signed) — each test overrides only the
 * fields it cares about.
 *
 * [ApkContext]'s constructor is `internal` (not `private`) specifically so this fixture builder
 * can construct real instances without going through [ApkContext.build], which needs a real
 * APK file + Android `Context`.
 */
fun fakeApkContext(
    apkFile: File = File("fixture.apk"),
    sha256: String = "0".repeat(64),
    sizeBytes: Long = 1_000_000L,
    packageName: String = "com.example.clean",
    versionName: String? = "1.0.0",
    permissions: Set<String> = emptySet(),
    targetSdk: Int = 34,
    minSdk: Int = 24,
    exportedComponentCount: Int = 2,
    hasDeviceAdminReceiver: Boolean = false,
    accessibility: ApkContext.AccessibilityInfo = ApkContext.AccessibilityInfo(
        declaresService = false,
        canRetrieveWindowContent = false,
        canPerformGestures = false,
        filtersKeyEvents = false,
    ),
    signerCertSha256: List<String> = emptyList(),
    isDebugSigned: Boolean = false,
    nativeLibs: List<String> = emptyList(),
    dexText: String = "",
    dexTruncated: Boolean = false,
    scanText: String = "",
    manifestText: String = "",
    hasAnyActivity: Boolean = true,
    manifestParseFailed: Boolean = false,
): ApkContext = ApkContext(
    apkFile = apkFile,
    sha256 = sha256,
    sizeBytes = sizeBytes,
    packageName = packageName,
    versionName = versionName,
    permissions = permissions,
    targetSdk = targetSdk,
    minSdk = minSdk,
    exportedComponentCount = exportedComponentCount,
    hasDeviceAdminReceiver = hasDeviceAdminReceiver,
    accessibility = accessibility,
    signerCertSha256 = signerCertSha256,
    isDebugSigned = isDebugSigned,
    nativeLibs = nativeLibs,
    dexText = dexText,
    dexTruncated = dexTruncated,
    scanText = scanText,
    manifestText = manifestText,
    hasAnyActivity = hasAnyActivity,
    manifestParseFailed = manifestParseFailed,
)
