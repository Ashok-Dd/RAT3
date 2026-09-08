import 'package:flutter/services.dart';
import 'package:rat3/core/utils/app_utils.dart';

/// Single gateway for ALL native Android calls via MethodChannel.
/// Every layer uses this service — no layer talks to the channel directly.
///
/// Channel name must match MainActivity.kt companion object CHANNEL constant:
///   "com.example.rat3/security"
class PlatformChannelService {
  static const String _tag = 'PlatformChannelService';

  static const MethodChannel _channel =
      MethodChannel('com.example.rat3/security');

  // ── CPU ────────────────────────────────────────────────────────────────────

  /// Returns real CPU usage 0.0–100.0.
  /// Returns -1.0 if /proc/stat is inaccessible (some restricted ROMs).
  Future<double> getCpuUsage() async {
    try {
      final result = await _channel.invokeMethod<double>('getCpuUsage');
      return result ?? -1.0;
    } on PlatformException catch (e) {
      AppLogger.error(_tag, 'getCpuUsage failed: ${e.message}');
      return -1.0;
    } catch (e) {
      AppLogger.error(_tag, 'getCpuUsage error', e);
      return -1.0;
    }
  }

  // ── Memory ─────────────────────────────────────────────────────────────────

  /// Returns {totalRam, availableRam, lowMemory, threshold} from ActivityManager.
  Future<Map<String, dynamic>> getMemoryInfo() async {
    try {
      final result = await _channel.invokeMapMethod<String, dynamic>('getMemoryInfo');
      return result ?? {};
    } on PlatformException catch (e) {
      AppLogger.error(_tag, 'getMemoryInfo failed: ${e.message}');
      return {};
    }
  }

  // ── Network Connections ────────────────────────────────────────────────────

  /// Returns real TCP connections parsed from /proc/net/tcp and /proc/net/tcp6.
  /// Each entry: {localAddress, remoteAddress, state, uid, source}
  Future<List<Map<String, dynamic>>> getNetworkConnections() async {
    try {
      final result = await _channel.invokeListMethod<dynamic>('getNetworkConnections');
      if (result == null) return [];
      return result
          .whereType<Map>()
          .map((e) => Map<String, dynamic>.from(e))
          .toList();
    } on PlatformException catch (e) {
      AppLogger.error(_tag, 'getNetworkConnections failed: ${e.message}');
      return [];
    }
  }

  // ── Network Data Usage ─────────────────────────────────────────────────────

  /// Returns {totalTxBytes, totalRxBytes, mobileTxBytes, mobileRxBytes}.
  /// Values are -1 if TrafficStats reports UNSUPPORTED.
  Future<Map<String, dynamic>> getNetworkDataUsage() async {
    try {
      final result = await _channel.invokeMapMethod<String, dynamic>('getNetworkDataUsage');
      return result ?? {};
    } on PlatformException catch (e) {
      AppLogger.error(_tag, 'getNetworkDataUsage failed: ${e.message}');
      return {};
    }
  }

  // ── Running Processes ──────────────────────────────────────────────────────

  /// Returns list of running app processes from ActivityManager.
  /// Each entry: {pid, processName, importance, importanceReasonCode, pkgList}
  Future<List<Map<String, dynamic>>> getRunningProcesses() async {
    try {
      final result = await _channel.invokeListMethod<dynamic>('getRunningProcesses');
      if (result == null) return [];
      return result
          .whereType<Map>()
          .map((e) => Map<String, dynamic>.from(e))
          .toList();
    } on PlatformException catch (e) {
      AppLogger.error(_tag, 'getRunningProcesses failed: ${e.message}');
      return [];
    }
  }

  // ── App Usage Stats ────────────────────────────────────────────────────────

  /// Returns per-app foreground usage stats for the past 24 hours.
  /// Requires PACKAGE_USAGE_STATS permission.
  /// Each entry: {packageName, totalTimeInForeground, lastTimeUsed}
  Future<List<Map<String, dynamic>>> getUsageStats() async {
    try {
      final result = await _channel.invokeListMethod<dynamic>('getUsageStats');
      if (result == null) return [];
      return result
          .whereType<Map>()
          .map((e) => Map<String, dynamic>.from(e))
          .toList();
    } on PlatformException catch (e) {
      // Error code USAGE_STATS_PERMISSION means user hasn't granted access yet
      AppLogger.warning(_tag, 'getUsageStats: ${e.code} — ${e.message}');
      return [];
    }
  }

  // ── Battery ────────────────────────────────────────────────────────────────

  /// Returns real battery info from ACTION_BATTERY_CHANGED broadcast.
  Future<Map<String, dynamic>> getBatteryInfo() async {
    try {
      final result = await _channel.invokeMapMethod<String, dynamic>('getBatteryInfo');
      return result ?? {};
    } on PlatformException catch (e) {
      AppLogger.error(_tag, 'getBatteryInfo failed: ${e.message}');
      return {};
    }
  }

  // ── Security Flags Bundle ──────────────────────────────────────────────────

  /// Returns all boolean security flags in one round-trip.
  /// Keys: isRooted, isDeveloperOptionsEnabled, isUsbDebuggingEnabled,
  ///       isIgnoringBatteryOptimizations, hasUsageStatsPermission
  Future<Map<String, dynamic>> getSecurityFlags() async {
    try {
      final result = await _channel.invokeMapMethod<String, dynamic>('getSecurityFlags');
      return result ?? {};
    } on PlatformException catch (e) {
      AppLogger.error(_tag, 'getSecurityFlags failed: ${e.message}');
      return {};
    }
  }

  // ── Installed Apps ─────────────────────────────────────────────────────────

  Future<List<Map<String, dynamic>>> getInstalledApps() async {
    try {
      final result = await _channel.invokeListMethod<dynamic>('getInstalledApps');
      if (result == null) return [];
      return result
          .whereType<Map>()
          .map((e) => Map<String, dynamic>.from(e))
          .toList();
    } on PlatformException catch (e) {
      AppLogger.error(_tag, 'getInstalledApps failed: ${e.message}');
      return [];
    }
  }

  // ── Battery Optimization ───────────────────────────────────────────────────

  Future<bool> requestBatteryOptimizationExemption() async {
    try {
      return await _channel.invokeMethod<bool>(
              'requestBatteryOptimizationExemption') ??
          false;
    } catch (e) {
      AppLogger.error(_tag, 'requestBatteryOptimizationExemption failed', e);
      return false;
    }
  }

  // ── Scan All Apps ─────────────────────────────────────────────────────────

  /// Full app audit. Kotlin does all heavy lifting on a background thread.
  /// Returns real data: permissions, install source, risk signals, usage time.
  Future<List<Map<String, dynamic>>> scanAllApps() async {
    try {
      final result = await _channel.invokeListMethod<dynamic>('scanAllApps');
      if (result == null) return [];
      return result
          .whereType<Map>()
          .map((e) => Map<String, dynamic>.from(e))
          .toList();
    } on PlatformException catch (e) {
      AppLogger.error(_tag, 'scanAllApps failed: ${e.message}');
      return [];
    }
  }

  // ── Active Sensors ────────────────────────────────────────────────────────

  /// Returns all hardware sensors available on device from SensorManager.
  Future<List<Map<String, dynamic>>> getActiveSensors() async {
    try {
      final result = await _channel.invokeListMethod<dynamic>('getActiveSensors');
      if (result == null) return [];
      return result
          .whereType<Map>()
          .map((e) => Map<String, dynamic>.from(e))
          .toList();
    } on PlatformException catch (e) {
      AppLogger.error(_tag, 'getActiveSensors failed: ${e.message}');
      return [];
    }
  }

  // ── Per-App Network Usage ─────────────────────────────────────────────────

  /// Real TX/RX bytes per app via TrafficStats UID mapping.
  Future<List<Map<String, dynamic>>> getAppNetworkUsage() async {
    try {
      final result = await _channel.invokeListMethod<dynamic>('getAppNetworkUsage');
      if (result == null) return [];
      return result
          .whereType<Map>()
          .map((e) => Map<String, dynamic>.from(e))
          .toList();
    } on PlatformException catch (e) {
      AppLogger.error(_tag, 'getAppNetworkUsage failed: ${e.message}');
      return [];
    }
  }

  // ── App Permissions (single app) ──────────────────────────────────────────

  // ── User Installed Apps (with sensor permissions) ─────────────────────────

  /// Calls handleGetUserAppsUsingSensors on the Kotlin side.
  /// Returns ALL installed packages — filtering happens in Dart.
  /// Requires QUERY_ALL_PACKAGES in AndroidManifest.xml.
  // ── Check if camera/mic are in use RIGHT NOW ──────────────────────────────
  //
  // Uses three hardware-level signals (see Kotlin for full explanation):
  //   1. /proc/asound status files → mic RUNNING
  //   2. Camera2 open attempt      → ERROR_CAMERA_IN_USE
  //   3. UsageEvents foreground    → suspects narrowed down
  //
  // Returns: { isMicInUse, isCameraInUse, suspectApps[], timestamp }
  Future<Map<String, dynamic>> checkSensorInUse() async {
    try {
      final raw = await _channel.invokeMethod<dynamic>('checkSensorInUse');
      if (raw == null) return {};
      final map = Map<String, dynamic>.from(raw as Map);
      // suspectApps is a list of maps
      final rawSuspects = map['suspectApps'] as List? ?? [];
      map['suspectApps'] = rawSuspects
          .whereType<Map>()
          .map((e) => Map<String, dynamic>.from(e))
          .toList();
      return map;
    } on PlatformException catch (e) {
      AppLogger.error(_tag, 'checkSensorInUse failed: ${e.message}');
      return {};
    } catch (e) {
      AppLogger.error(_tag, 'checkSensorInUse unexpected error', e);
      return {};
    }
  }

  Future<List<Map<String, dynamic>>> getUserInstalledSensorApps() async {
    try {
      final result = await _channel.invokeListMethod<dynamic>(
        'getUserInstalledSensorApps',
      );
      if (result == null) {
        AppLogger.warning(_tag, 'getUserInstalledSensorApps: null result');
        return [];
      }
      return result
          .whereType<Map>()
          .map((e) => Map<String, dynamic>.from(e))
          .toList();
    } on PlatformException catch (e) {
      AppLogger.error(_tag, 'getUserInstalledSensorApps failed: ${e.message}');
      return [];
    } catch (e) {
      AppLogger.error(_tag, 'getUserInstalledSensorApps unexpected error', e);
      return [];
    }
  }

  // ── Foreground Service Control ─────────────────────────────────────────

  /// Starts the native Android ScanForegroundService.
  Future<bool> startForegroundService({int intervalMinutes = 10}) async {
    try {
      final result = await _channel.invokeMethod<bool>(
        'startForegroundService',
        {'intervalMinutes': intervalMinutes},
      );
      return result ?? false;
    } on PlatformException catch (e) {
      AppLogger.error(_tag, 'startForegroundService failed: ${e.message}');
      return false;
    }
  }

  /// Stops the native Android ScanForegroundService.
  Future<bool> stopForegroundService() async {
    try {
      final result = await _channel.invokeMethod<bool>('stopForegroundService');
      return result ?? false;
    } on PlatformException catch (e) {
      AppLogger.error(_tag, 'stopForegroundService failed: ${e.message}');
      return false;
    }
  }

  // ── Settings deep-links (for onboarding) ──────────────────────────────────

  /// Opens the system "Usage access" settings page for this app.
  Future<void> openUsageAccessSettings() async {
    try {
      await _channel.invokeMethod<void>('openUsageAccessSettings');
    } catch (e) {
      AppLogger.error(_tag, 'openUsageAccessSettings failed', e);
    }
  }

  /// Opens the system "Accessibility" settings page.
  Future<void> openAccessibilitySettings() async {
    try {
      await _channel.invokeMethod<void>('openAccessibilitySettings');
    } catch (e) {
      AppLogger.error(_tag, 'openAccessibilitySettings failed', e);
    }
  }

   // ── New Strengthened Detection Methods ─────────────────────────────────────

  /// Real active accessibility services — actually ENABLED by user in Settings.
  /// Returns list of {packageName, appName, serviceName, isSystemApp, capabilities}
  Future<List<Map<String, dynamic>>> getActiveAccessibilityServices() async {
    try {
      final result = await _channel.invokeListMethod<dynamic>(
        'getActiveAccessibilityServices',
      );
      if (result == null) return [];
      return result.whereType<Map>()
          .map((e) => Map<String, dynamic>.from(e)).toList();
    } on PlatformException catch (e) {
      AppLogger.error(_tag, 'getActiveAccessibilityServices failed: ${e.message}');
      return [];
    }
  }

  /// Screen recording detection via MediaProjectionManager + known recorder apps.
  /// Returns {isRecording: bool, suspectApps: List<String>}
  Future<Map<String, dynamic>> isScreenRecordingActive() async {
    try {
      final raw = await _channel.invokeMethod<dynamic>('isScreenRecordingActive');
      if (raw == null) return {'isRecording': false, 'suspectApps': []};
      if (raw is Map) return Map<String, dynamic>.from(raw);
      return {'isRecording': false, 'suspectApps': []};
    } on PlatformException catch (e) {
      AppLogger.error(_tag, 'isScreenRecordingActive failed: ${e.message}');
      return {'isRecording': false, 'suspectApps': []};
    }
  }

  /// Clipboard monitoring risk check.
  /// Returns {suspectCount: int, suspectApps: List, hasClipboardContent: bool}
  Future<Map<String, dynamic>> getClipboardInfo() async {
    try {
      final raw = await _channel.invokeMethod<dynamic>('getClipboardInfo');
      if (raw == null) return {'suspectCount': 0, 'suspectApps': []};
      if (raw is Map) return Map<String, dynamic>.from(raw);
      return {'suspectCount': 0, 'suspectApps': []};
    } on PlatformException catch (e) {
      AppLogger.error(_tag, 'getClipboardInfo failed: ${e.message}');
      return {'suspectCount': 0, 'suspectApps': []};
    }
  }

  /// Full detailed security flags — replaces getSecurityFlags() with more signals.
  /// Adds: real accessibility count, real admin count, unknown sources (per-app
  /// on Android 8+), mock location, verify apps disabled, battery opt count.
  Future<Map<String, dynamic>> getDetailedSecurityFlags() async {
    try {
      final result = await _channel.invokeMapMethod<String, dynamic>(
        'getDetailedSecurityFlags',
      );
      return result ?? {};
    } on PlatformException catch (e) {
      AppLogger.error(_tag, 'getDetailedSecurityFlags failed: ${e.message}');
      return {};
    }
  }

  /// Detects active VPN connections — used by RATs to tunnel exfiltrated data.
  Future<Map<String, dynamic>> getVpnStatus() async {
    try {
      final raw = await _channel.invokeMethod<dynamic>('getVpnStatus');
      if (raw == null) return {};
      return Map<String, dynamic>.from(raw as Map);
    } on PlatformException catch (e) {
      AppLogger.error(_tag, 'getVpnStatus failed: ${e.message}');
      return {};
    }
  }
}

 