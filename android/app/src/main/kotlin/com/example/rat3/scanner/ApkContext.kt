package com.example.rat3.scanner

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import java.io.File
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.zip.ZipEntry
import java.util.zip.ZipFile

/**
 * Everything the four analysis layers need about one APK, parsed exactly once.
 *
 * Previously each layer re-opened the ZIP, re-read the manifest and re-decoded the DEX files,
 * with three different ad-hoc permission-extraction hacks and an unbounded DEX read that could
 * OOM on multidex apps. [ApkContext] fixes all of that: one parse, bounded reads, and the
 * manifest handled by the platform ([PackageManager.getPackageArchiveInfo]) instead of a
 * fragile hand-rolled binary-XML parser.
 *
 * Build it on a background thread via [ApkContext.build].
 */
class ApkContext private constructor(
    val apkFile: File,
    val sha256: String,
    val sizeBytes: Long,
    val packageName: String,
    val versionName: String?,
    val permissions: Set<String>,
    val targetSdk: Int,
    val minSdk: Int,
    val exportedComponentCount: Int,
    val hasDeviceAdminReceiver: Boolean,
    val accessibility: AccessibilityInfo,
    val signerCertSha256: List<String>,
    val isDebugSigned: Boolean,
    val nativeLibs: List<String>,
    val dexText: String,
    val dexTruncated: Boolean,
    val scanText: String,
    val manifestParseFailed: Boolean,
) {

    /** Accessibility-service capabilities declared under res/xml (RAT / banker fingerprint). */
    data class AccessibilityInfo(
        val declaresService: Boolean,
        val canRetrieveWindowContent: Boolean,
        val canPerformGestures: Boolean,
        val filtersKeyEvents: Boolean,
    ) {
        val isAbusive: Boolean get() = declaresService && (canRetrieveWindowContent || canPerformGestures)
    }

    fun hasPermission(permission: String): Boolean = permission in permissions

    companion object {
        private const val MANIFEST_ENTRY = "AndroidManifest.xml"

        private val TEXT_EXTENSIONS = setOf("dex", "xml", "json", "js", "html", "txt", "properties")
        private val NATIVE_LIB_SUFFIX = ".so"
        private val DEX_ENTRY = Regex("""(^|/)classes\d*\.dex$""")
        private val ACCESSIBILITY_XML = Regex("""res/xml.*\.xml$""")

        /** Well-known subject DN fragment of every Android debug-keystore certificate. */
        private const val DEBUG_CERT_DN = "Android Debug"

        /**
         * Parses [apkFile] once. Never throws for a merely-unparseable manifest — callers get an
         * [ApkContext] with [manifestParseFailed] set and empty manifest-derived fields.
         *
         * @throws java.io.IOException if the file is not a readable ZIP at all
         */
        fun build(context: Context, apkFile: File): ApkContext {
            val sha256 = sha256Of(apkFile)
            val size = apkFile.length()

            val pkg = readArchiveInfo(context, apkFile)
            val manifestFailed = pkg == null

            val permissions = pkg?.requestedPermissions?.toSet()
                ?: rawScanPermissions(apkFile)
            val targetSdk = pkg?.applicationInfo?.targetSdkVersion ?: 0
            val minSdk = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                pkg?.applicationInfo?.minSdkVersion ?: 0
            } else {
                0
            }
            val exported = countExportedComponents(pkg)
            val deviceAdmin = hasDeviceAdminReceiver(pkg)

            val (certHashes, debugSigned) = readSigning(context, apkFile)

            var dexBytes = 0
            var dexTruncated = false
            val dexBuilder = StringBuilder()
            val resourceBuilder = StringBuilder()
            val nativeLibs = mutableListOf<String>()
            val accessibilityXml = StringBuilder()
            var resourceBytes = 0
            var resourceEntries = 0
            var manifestBytesText = ""

            ZipFile(apkFile).use { zip ->
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val entry = entries.nextElement()
                    if (entry.isDirectory) continue
                    val name = entry.name

                    when {
                        name.endsWith(NATIVE_LIB_SUFFIX) -> nativeLibs += name

                        DEX_ENTRY.containsMatchIn(name) -> {
                            if (!dexTruncated) {
                                val remaining = ScannerConfig.Limits.DEX_TEXT_MAX_BYTES - dexBytes
                                val chunk = readEntryText(zip, entry, remaining)
                                dexBuilder.append(chunk)
                                dexBytes += chunk.length
                                if (dexBytes >= ScannerConfig.Limits.DEX_TEXT_MAX_BYTES) dexTruncated = true
                            }
                        }

                        name == MANIFEST_ENTRY -> {
                            manifestBytesText = readEntryText(zip, entry, 512 * 1024)
                        }

                        ACCESSIBILITY_XML.containsMatchIn(name) -> {
                            if (accessibilityXml.length < ScannerConfig.Limits.ACCESSIBILITY_XML_MAX_BYTES) {
                                accessibilityXml.append(readEntryText(zip, entry, 64 * 1024))
                            }
                        }

                        name.substringAfterLast('.', "").lowercase() in TEXT_EXTENSIONS -> {
                            if (resourceEntries < ScannerConfig.Limits.RESOURCE_TEXT_MAX_ENTRIES &&
                                resourceBytes < ScannerConfig.Limits.RESOURCE_TEXT_MAX_BYTES
                            ) {
                                val remaining = ScannerConfig.Limits.RESOURCE_TEXT_MAX_BYTES - resourceBytes
                                val chunk = readEntryText(zip, entry, remaining)
                                resourceBuilder.append(chunk)
                                resourceBytes += chunk.length
                                resourceEntries++
                            }
                        }
                    }
                }
            }

            val dexText = dexBuilder.toString()
            val resourceText = resourceBuilder.toString()
            val scanText = buildString {
                append(dexText)
                append('\n')
                append(manifestBytesText)
                append('\n')
                append(resourceText)
            }

            return ApkContext(
                apkFile = apkFile,
                sha256 = sha256,
                sizeBytes = size,
                packageName = pkg?.packageName ?: "",
                versionName = pkg?.versionName,
                permissions = permissions,
                targetSdk = targetSdk,
                minSdk = minSdk,
                exportedComponentCount = exported,
                hasDeviceAdminReceiver = deviceAdmin,
                accessibility = parseAccessibility(permissions, accessibilityXml.toString()),
                signerCertSha256 = certHashes,
                isDebugSigned = debugSigned,
                nativeLibs = nativeLibs,
                dexText = dexText,
                dexTruncated = dexTruncated,
                scanText = scanText,
                manifestParseFailed = manifestFailed,
            )
        }

        // ── manifest / package info ───────────────────────────────────────────────────────

        @Suppress("DEPRECATION")
        private fun readArchiveInfo(context: Context, apkFile: File): PackageInfo? {
            val flags = PackageManager.GET_PERMISSIONS or
                PackageManager.GET_ACTIVITIES or
                PackageManager.GET_SERVICES or
                PackageManager.GET_RECEIVERS or
                PackageManager.GET_PROVIDERS or
                PackageManager.GET_META_DATA
            return try {
                context.packageManager.getPackageArchiveInfo(apkFile.absolutePath, flags)
            } catch (t: Throwable) {
                ScanLog.w("ApkContext.readArchiveInfo", t)
                null
            }
        }

        private fun countExportedComponents(pkg: PackageInfo?): Int {
            if (pkg == null) return 0
            var n = 0
            pkg.activities?.forEach { if (it.exported) n++ }
            pkg.services?.forEach { if (it.exported) n++ }
            pkg.receivers?.forEach { if (it.exported) n++ }
            pkg.providers?.forEach { if (it.exported) n++ }
            return n
        }

        private fun hasDeviceAdminReceiver(pkg: PackageInfo?): Boolean {
            val receivers = pkg?.receivers ?: return false
            return receivers.any { it.permission == "android.permission.BIND_DEVICE_ADMIN" }
        }

        private fun parseAccessibility(permissions: Set<String>, xml: String): AccessibilityInfo {
            val declares = "android.permission.BIND_ACCESSIBILITY_SERVICE" in permissions ||
                xml.contains("accessibility-service")
            if (!declares) return AccessibilityInfo(false, false, false, false)
            return AccessibilityInfo(
                declaresService = true,
                canRetrieveWindowContent = xml.contains("canRetrieveWindowContent=\"true\"") ||
                    xml.contains("canRetrieveWindowContent=\"0xffffffff\""),
                canPerformGestures = xml.contains("canPerformGestures=\"true\""),
                filtersKeyEvents = xml.contains("flagRequestFilterKeyEvents"),
            )
        }

        // ── signing ──────────────────────────────────────────────────────────────────────

        @Suppress("DEPRECATION")
        private fun readSigning(context: Context, apkFile: File): Pair<List<String>, Boolean> {
            return try {
                val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    PackageManager.GET_SIGNING_CERTIFICATES
                } else {
                    PackageManager.GET_SIGNATURES
                }
                val info = context.packageManager.getPackageArchiveInfo(apkFile.absolutePath, flags)
                    ?: return emptyList<String>() to false

                val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    info.signingInfo?.apkContentsSigners
                } else {
                    info.signatures
                } ?: return emptyList<String>() to false

                val cf = CertificateFactory.getInstance("X.509")
                val hashes = mutableListOf<String>()
                var debugSigned = false
                for (sig in signatures) {
                    val bytes = sig.toByteArray()
                    hashes += hexSha256(bytes)
                    runCatching {
                        val cert = cf.generateCertificate(bytes.inputStream()) as X509Certificate
                        if (cert.subjectDN.name.contains(DEBUG_CERT_DN)) debugSigned = true
                    }
                }
                hashes to debugSigned
            } catch (t: Throwable) {
                ScanLog.w("ApkContext.readSigning", t)
                emptyList<String>() to false
            }
        }

        // ── raw fallbacks / low-level readers ────────────────────────────────────────────

        /** Fallback used only when [getPackageArchiveInfo] cannot parse the manifest. */
        private fun rawScanPermissions(apkFile: File): Set<String> = try {
            ZipFile(apkFile).use { zip ->
                val entry = zip.getEntry(MANIFEST_ENTRY) ?: return emptySet()
                val raw = zip.getInputStream(entry).use { it.readBytes() }
                    .toString(Charsets.ISO_8859_1)
                (KnownPermissions.DANGEROUS + KnownPermissions.SUSPICIOUS)
                    .filter { raw.contains(it) }
                    .toSet()
            }
        } catch (t: Throwable) {
            ScanLog.w("ApkContext.rawScanPermissions", t)
            emptySet()
        }

        private fun readEntryText(zip: ZipFile, entry: ZipEntry, maxBytes: Int): String {
            if (maxBytes <= 0) return ""
            return zip.getInputStream(entry).use { stream ->
                val buf = ByteArray(minOf(maxBytes, 1 shl 20))
                val out = StringBuilder()
                var total = 0
                while (total < maxBytes) {
                    val read = stream.read(buf)
                    if (read <= 0) break
                    out.append(String(buf, 0, read, Charsets.ISO_8859_1))
                    total += read
                }
                out.toString()
            }
        }

        private fun sha256Of(file: File): String {
            val md = MessageDigest.getInstance("SHA-256")
            file.inputStream().use { input ->
                val buf = ByteArray(1 shl 16)
                while (true) {
                    val read = input.read(buf)
                    if (read <= 0) break
                    md.update(buf, 0, read)
                }
            }
            return md.digest().toHex()
        }

        private fun hexSha256(bytes: ByteArray): String =
            MessageDigest.getInstance("SHA-256").digest(bytes).toHex()

        private fun ByteArray.toHex(): String =
            joinToString("") { "%02x".format(it) }
    }
}
