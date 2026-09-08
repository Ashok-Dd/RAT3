import 'dart:math';
import 'package:rat3/core/utils/app_utils.dart';
import 'package:rat3/data/models/app_models.dart';
import 'package:rat3/data/services/platform_channel_service.dart';
import 'package:rat3/layers/feature_engine/device_features.dart';
import 'package:rat3/layers/network_monitor/network_monitor.dart';
import 'package:rat3/core/constants/app_constants.dart';


/// FeatureCollector
///
/// Gathers raw data from every available Android API and assembles
/// the full DeviceFeatures snapshot. This is NOT the scorer —
/// it just collects and normalises the raw signals.
///
/// Data sources used:
///   PlatformChannelService.checkSensorInUse()     → mic/camera hardware state
///   PlatformChannelService.getUserSensorApps()    → per-app sensor permissions
///   PlatformChannelService.getSecurityFlags()     → root, USB debug, dev options
///   PlatformChannelService.getCpuUsage()          → real /proc/stat CPU %
///   PlatformChannelService.getMemoryInfo()        → ActivityManager.MemoryInfo
///   PlatformChannelService.getBatteryInfo()       → BatteryManager
///   PlatformChannelService.getRunningProcesses()  → ActivityManager processes
///   PlatformChannelService.getUsageStats()        → UsageStatsManager 24h
///   PlatformChannelService.scanAllApps()          → full installed app audit
///   PlatformChannelService.getAppNetworkUsage()   → TrafficStats per-UID
///   NetworkMonitor.detectedConnections            → already-classified connections
class FeatureCollector {
  static const String _tag = 'FeatureCollector';

  final PlatformChannelService _platform;
  final NetworkMonitor _networkMonitor;

  // Rolling history for variance and correlation
  final List<double> _cpuHistory        = [];
  final List<double> _memHistory        = [];
  final List<bool>   _micHistory        = [];   // was mic active at each poll
  final List<bool>   _networkHistory    = [];   // was background TX > 0 at each poll
  DateTime?          _lastBatteryCheck;
  double             _lastBatteryLevel  = -1;

  FeatureCollector({
    required PlatformChannelService platform,
    required NetworkMonitor networkMonitor,
  })  : _platform = platform,
        _networkMonitor = networkMonitor;

  /// Collect all features in one shot.
  /// Takes ~1–2 seconds on most devices.
  Future<DeviceFeatures> collect() async {
    final now    = DateTime.now();
    final isIdle = _isIdleHour(now.hour);  // 23:00–06:00

    // ── Gather raw data in parallel where safe ────────────────────────────
    final results = await Future.wait([
      _platform.checkSensorInUse(),          // 0
      _platform.getSecurityFlags(),          // 1
      _platform.getCpuUsage(),              // 2  (returns double directly)
      _platform.getMemoryInfo(),            // 3
      _platform.getBatteryInfo(),           // 4
      _platform.getRunningProcesses(),      // 5
      _platform.getUsageStats(),            // 6
      _platform.scanAllApps(),              // 7
      _platform.getAppNetworkUsage(),       // 8
      _platform.getUserInstalledSensorApps(), // 9
    ]);

    final sensorStatus  = results[0] as Map<String, dynamic>;
    final secFlags      = results[1] as Map<String, dynamic>;
    final cpuUsage      = (results[2] as double?) ?? 0.0;
    final memInfo       = results[3] as Map<String, dynamic>;
    final batteryInfo   = results[4] as Map<String, dynamic>;
    final processes     = results[5] as List<Map<String, dynamic>>;
    final usageStats    = results[6] as List<Map<String, dynamic>>;
    final scannedApps   = results[7] as List<Map<String, dynamic>>;
    final netUsage      = results[8] as List<Map<String, dynamic>>;
    final sensorApps    = results[9] as List<Map<String, dynamic>>;

    // ── SENSOR ────────────────────────────────────────────────────────────
    final cameraActiveNow = sensorStatus['isCameraInUse'] as bool? ?? false;
    final micActiveNow    = sensorStatus['isMicInUse']    as bool? ?? false;

    // Track mic history for correlation
    _micHistory.add(micActiveNow);
    if (_micHistory.length > 20) _micHistory.removeAt(0);

    // Count user apps with sensor permissions
    final userApps = sensorApps.where((a) => !(a['isSystemApp'] as bool? ?? false)).toList();
    int camPerm = 0, camRecentFg = 0;
    int micPerm = 0, micRecentFg = 0;
    int locPerm = 0, locBgPerm = 0;

    for (final a in userApps) {
      final granted  = List<String>.from(a['grantedSensors'] as List? ?? []);
      final recentFg = a['isCurrentlyRunning'] as bool? ?? false;
      if (granted.contains('android.permission.CAMERA')) {
        camPerm++;
        if (recentFg) camRecentFg++;
      }
      if (granted.contains('android.permission.RECORD_AUDIO')) {
        micPerm++;
        if (recentFg) micRecentFg++;
      }
      if (granted.contains('android.permission.ACCESS_FINE_LOCATION') ||
          granted.contains('android.permission.ACCESS_COARSE_LOCATION')) {
        locPerm++;
      }
      if (granted.contains('android.permission.ACCESS_BACKGROUND_LOCATION')) {
        locBgPerm++;
      }
    }

    // Sensor entropy: how many different sensors fired in this session
    // Uses Shannon entropy on the active sensor pattern
    final sensorPattern = [cameraActiveNow, micActiveNow, locBgPerm > 0];
    final activeCount   = sensorPattern.where((b) => b).length;
    final entropy       = _shannonEntropy(activeCount, sensorPattern.length);

    // Sensor irregularity: sensors active when they shouldn't be
    double sensorIrregularity = 0;
    if (cameraActiveNow && isIdle) sensorIrregularity += 40;
    if (micActiveNow    && isIdle) sensorIrregularity += 40;
    if (cameraActiveNow && locBgPerm > 0) sensorIrregularity += 20;
    sensorIrregularity = sensorIrregularity.clamp(0, 100);

    // ── PERMISSIONS ───────────────────────────────────────────────────────
    // Count across all scanned user apps
    final dangerousPerms = _sumField(scannedApps, 'dangerousGranted');
    final highRiskPerms  = _sumField(scannedApps, 'grantedHighRisk');

    // Accessibility + device admin from security flags
    final accessibilityActive = secFlags['isAccessibilityServiceActive'] as bool? ?? false;
    final deviceAdminActive   = secFlags['isDeviceAdminActive']          as bool? ?? false;
    final activeAdminCount    = (secFlags['activeDeviceAdminCount'] as num?)?.toInt() ?? 0;
    final unknownSources      = secFlags['isUnknownSourcesEnabled']      as bool? ?? false;

    // Unused-but-granted ratio:
    // permissions granted to apps that haven't been used in 7+ days
    int totalGranted = 0, unusedGranted = 0;
    for (final app in scannedApps) {
      final dangerous   = (app['dangerousGranted'] as List?)?.length ?? 0;
      final bgTimeHrs   = (app['backgroundTimeHrs'] as num?)?.toDouble() ?? 0.0;
      final installDays = (app['installDaysAgo']    as num?)?.toInt() ?? 0;
      totalGranted += dangerous;
      // App installed 7+ days ago but 0 foreground time = unused
      if (bgTimeHrs == 0 && installDays > 7) unusedGranted += dangerous;
    }
    final unusedRatio = totalGranted > 0
        ? unusedGranted / totalGranted
        : 0.0;

    // Permission-vs-usage mismatch:
    // apps that have high-risk permissions but near-zero usage time
    int mismatchApps = 0;
    for (final app in scannedApps) {
      final highRisk  = (app['grantedHighRisk'] as List?)?.length ?? 0;
      final bgTimeHrs = (app['backgroundTimeHrs'] as num?)?.toDouble() ?? 0.0;
      if (highRisk >= 2 && bgTimeHrs < 0.1) mismatchApps++;
    }
    final permMismatch = (mismatchApps / (scannedApps.length.clamp(1, 9999)) * 100)
        .clamp(0.0, 100.0);

    // ── APP BEHAVIOR ──────────────────────────────────────────────────────
    final totalUserApps   = scannedApps.length;
    final sideloadedApps  = scannedApps.where((a) => a['isSideloaded'] as bool? ?? false).length;
    final unknownInstaller= scannedApps.where((a) {
      final src = a['installSource'] as String? ?? '';
      return src == 'unknown' || src == 'sideloaded';
    }).length;
    final recentInstalls  = scannedApps.where((a) => a['isRecentInstall'] as bool? ?? false).length;
    final oldSdkApps      = scannedApps.where((a) {
      final sdk = (a['targetSdkVersion'] as num?)?.toInt() ?? 30;
      return sdk < 26; // Pre-Oreo targeting
    }).length;

    // Running background process count from ActivityManager
    final bgProcesses = processes.where((p) {
      final imp = (p['importance'] as num?)?.toInt() ?? 0;
      return imp >= 400;
    }).length;

    // Apps with activity during idle hours (UsageStats lastTimeUsed)
    final idleHourApps = usageStats.where((s) {
      final lastUsed = (s['lastTimeUsed'] as num?)?.toInt() ?? 0;
      if (lastUsed == 0) return false;
      final dt = DateTime.fromMillisecondsSinceEpoch(lastUsed);
      return _isIdleHour(dt.hour);
    }).length;

    // Install/uninstall rate (installs in past 7 days / 7)
    final installRate = recentInstalls / 7.0;

    // ── SYSTEM ────────────────────────────────────────────────────────────
    final rootDetected  = secFlags['isRooted']                 as bool? ?? false;
    final usbDebugging  = secFlags['isUsbDebuggingEnabled']    as bool? ?? false;
    final devOptions    = secFlags['isDeveloperOptionsEnabled'] as bool? ?? false;

    // Battery optimization exceptions count
    final batteryOptDisabled = (secFlags['batteryOptDisabledCount'] as num?)?.toInt() ?? 0;

    // Memory
    final totalMem     = (memInfo['totalRam']     as num?)?.toInt() ?? 1;
    final availMem     = (memInfo['availableRam'] as num?)?.toInt() ?? 1;
    final memPct       = ((totalMem - availMem) / totalMem * 100).clamp(0.0, 100.0);

    // CPU history for variance
    _cpuHistory.add(cpuUsage);
    if (_cpuHistory.length > 10) _cpuHistory.removeAt(0);
    _memHistory.add(memPct);
    if (_memHistory.length > 10) _memHistory.removeAt(0);

    // Battery drain rate
    final battLevel  = (batteryInfo['level']    as num?)?.toDouble() ?? -1;
    final battDrain  = _computeBatteryDrain(battLevel, now);

    // CPU when screen off — approximation via recent history
    // When screen is off our process is in background, CPU should be near 0
    // If it's high, something is running
    final cpuWhenScreenOff = cpuUsage; // real-time reading, use as proxy

    // Screen on/usage ratio — using total foreground time vs uptime
    final totalFgMs = usageStats.fold<int>(
        0, (s, a) => s + ((a['totalTimeInForeground'] as num?)?.toInt() ?? 0));
    final screenOnRatio = _computeScreenRatio(totalFgMs);

    // ── NETWORK ───────────────────────────────────────────────────────────
    double totalBgSentMb = 0, totalBgRecvMb = 0;
    int uniqueIps = 0;
    bool smallPackets = false;

    for (final app in netUsage) {
      final tx = (app['txBytes'] as num?)?.toInt() ?? 0;
      final rx = (app['rxBytes'] as num?)?.toInt() ?? 0;
      totalBgSentMb += tx / (1024 * 1024);
      totalBgRecvMb += rx / (1024 * 1024);
    }

    // From classified connections
    final recentConns  = _networkMonitor.detectedConnections
        .where((c) => DateTime.now().difference(c.detectedAt).inHours < 1)
        .toList();
    final malCount  = recentConns.where((c) => c.category == TrafficCategory.malicious).length;
    final suspCount = recentConns.where((c) => c.category == TrafficCategory.suspicious).length;

    // Unique remote IPs
    final ipSet = recentConns.map((c) => c.ipAddress).toSet();
    uniqueIps = ipSet.length;

    // Frequent small packets: many connections with very low bytes each
    final smallConnections = recentConns.where((c) => c.totalBytes < 1024).length;
    smallPackets = smallConnections > 5;

    // Track network history for correlation
    final hasActiveTx = totalBgSentMb > 0;
    _networkHistory.add(hasActiveTx);
    if (_networkHistory.length > 20) _networkHistory.removeAt(0);

    // Data sent during idle hours
    final idleConns = recentConns.where((c) => _isIdleHour(c.detectedAt.hour));
    final idleSentMb = idleConns.fold<double>(
        0, (s, c) => s + c.bytesSent / (1024 * 1024));

    // Data sent without interaction = TX when no foreground apps active
    final noFgActive = usageStats.where((s) {
      final t = (s['totalTimeInForeground'] as num?)?.toInt() ?? 0;
      return t > 0;
    }).isEmpty;
    final dataSentNoInteraction = noFgActive ? totalBgSentMb : 0.0;

    // CPU spikes when screen off count
    final cpuSpikesScreenOff = _cpuHistory.where((c) => c > 60).length.toDouble();

    // Memory variance
    final memVariance = _variance(_memHistory);

    // ── CORRELATIONS ─────────────────────────────────────────────────────
    // Mic active AND network TX > 0 in same window
    final micAndNet   = micActiveNow && totalBgSentMb > 0.1;
    final camAndNet   = cameraActiveNow && totalBgSentMb > 0.1;
    final sensorAndNet= (micActiveNow || cameraActiveNow) && totalBgSentMb > 0.1;

    // Sensor-to-network correlation: ratio of history windows where both were true
    double sensorNetCorrelation = 0;
    if (_micHistory.length >= 5 && _networkHistory.length >= 5) {
      int coActive = 0;
      final len = min(_micHistory.length, _networkHistory.length);
      for (int i = 0; i < len; i++) {
        if (_micHistory[i] && _networkHistory[i]) coActive++;
      }
      sensorNetCorrelation = coActive / len;
    }

    // ── AGGREGATED ───────────────────────────────────────────────────────
    // FG to BG ratio: high foreground time = normal, high BG = suspicious
    final avgFgMs    = totalFgMs / usageStats.length.clamp(1, 9999);
    final bgRatio    = bgProcesses > 0 ? (avgFgMs / (bgProcesses * 3600000)).clamp(0.1, 10.0) : 1.0;

    // Idle anomaly score: activity concentration in 23:00–06:00
    double idleAnomaly = 0;
    if (isIdle) idleAnomaly += 20;
    if (cameraActiveNow && isIdle) idleAnomaly += 30;
    if (micActiveNow    && isIdle) idleAnomaly += 30;
    if (idleSentMb > 1) idleAnomaly += 20;
    idleAnomaly = idleAnomaly.clamp(0.0, 100.0);

    AppLogger.info(_tag, 'Features collected — ${DeviceFeatures(
      collectedAt: now,
      cameraActiveNow: cameraActiveNow,
      cameraAppsWithPermission: camPerm,
      cameraAppsRecentFg: camRecentFg,
      cameraActiveWhenScreenOff: cameraActiveNow && cpuUsage < 5,
      cameraActiveDuringIdle: cameraActiveNow && isIdle,
      micActiveNow: micActiveNow,
      micAppsWithPermission: micPerm,
      micAppsRecentFg: micRecentFg,
      micActiveOutsideCalls: micActiveNow,
      micActiveWhenScreenOff: micActiveNow && cpuUsage < 5,
      micActiveDuringIdle: micActiveNow && isIdle,
      locationAppsWithPermission: locPerm,
      locationBgAppsCount: locBgPerm,
      locationActiveDuringIdle: locBgPerm > 0 && isIdle,
      sensorActivityEntropy: entropy,
      sensorUsageIrregularity: sensorIrregularity,
      dangerousPermissionCount: dangerousPerms,
      highRiskPermissionCount: highRiskPerms,
      cameraPermissionGranted: camPerm > 0,
      micPermissionGranted: micPerm > 0,
      locationPermissionGranted: locPerm > 0,
      bgLocationPermissionGranted: locBgPerm > 0,
      accessibilityPermissionActive: accessibilityActive,
      deviceAdminActive: deviceAdminActive,
      unusedButGrantedRatio: unusedRatio,
      permissionsVsUsageMismatch: permMismatch,
      totalUserInstalledApps: totalUserApps,
      nonPlayStoreAppCount: sideloadedApps,
      recentlyInstalledAppCount: recentInstalls,
      unknownInstallerAppCount: unknownInstaller,
      appsTargetingOldSdkCount: oldSdkApps,
      appsWithAccessibilityCount: accessibilityActive ? 1 : 0,
      appsRunningInBgCount: bgProcesses,
      backgroundServicesActiveCount: bgProcesses,
      appsRunningDuringIdleCount: idleHourApps,
      appInstallRatePerWeek: installRate,
      appUninstallRatePerWeek: 0,
      frequentInstallUninstallPattern: recentInstalls > 3,
      developerOptionsEnabled: devOptions,
      usbDebuggingEnabled: usbDebugging,
      unknownSourcesEnabled: unknownSources,
      batteryOptDisabledAppsCount: batteryOptDisabled,
      cpuUsagePercent: cpuUsage,
      cpuUsageWhenScreenOff: cpuWhenScreenOff,
      screenOnToUsageRatio: screenOnRatio,
      rootDetected: rootDetected,
      activeDeviceAdminCount: activeAdminCount,
      accessibilityServicesActive: accessibilityActive,
      memoryUsagePercent: memPct,
      batteryDrainRatePerHour: battDrain,
      bgDataSentMb: totalBgSentMb,
      bgDataReceivedMb: totalBgRecvMb,
      dataSentDuringIdleMb: idleSentMb,
      dataSentWithoutInteraction: dataSentNoInteraction,
      uniqueRemoteIpsCount: uniqueIps,
      frequentSmallPackets: smallPackets,
      cpuSpikesWhenScreenOff: cpuSpikesScreenOff,
      memoryUsageVariance: memVariance,
      maliciousConnectionCount: malCount,
      suspiciousConnectionCount: suspCount,
      dataSentWhenMicActive: micAndNet,
      dataSentWhenCameraActive: camAndNet,
      networkDuringSensorUsage: sensorAndNet,
      fgToBgActivityRatio: bgRatio,
      sensorToNetworkCorrelation: sensorNetCorrelation,
      overallIdleAnomalyScore: idleAnomaly,
    ).summary}');

    return DeviceFeatures(
      collectedAt: now,
      cameraActiveNow: cameraActiveNow,
      cameraAppsWithPermission: camPerm,
      cameraAppsRecentFg: camRecentFg,
      cameraActiveWhenScreenOff: cameraActiveNow && cpuUsage < 5,
      cameraActiveDuringIdle: cameraActiveNow && isIdle,
      micActiveNow: micActiveNow,
      micAppsWithPermission: micPerm,
      micAppsRecentFg: micRecentFg,
      micActiveOutsideCalls: micActiveNow,
      micActiveWhenScreenOff: micActiveNow && cpuUsage < 5,
      micActiveDuringIdle: micActiveNow && isIdle,
      locationAppsWithPermission: locPerm,
      locationBgAppsCount: locBgPerm,
      locationActiveDuringIdle: locBgPerm > 0 && isIdle,
      sensorActivityEntropy: entropy,
      sensorUsageIrregularity: sensorIrregularity,
      dangerousPermissionCount: dangerousPerms,
      highRiskPermissionCount: highRiskPerms,
      cameraPermissionGranted: camPerm > 0,
      micPermissionGranted: micPerm > 0,
      locationPermissionGranted: locPerm > 0,
      bgLocationPermissionGranted: locBgPerm > 0,
      accessibilityPermissionActive: accessibilityActive,
      deviceAdminActive: deviceAdminActive,
      unusedButGrantedRatio: unusedRatio,
      permissionsVsUsageMismatch: permMismatch,
      totalUserInstalledApps: totalUserApps,
      nonPlayStoreAppCount: sideloadedApps,
      recentlyInstalledAppCount: recentInstalls,
      unknownInstallerAppCount: unknownInstaller,
      appsTargetingOldSdkCount: oldSdkApps,
      appsWithAccessibilityCount: accessibilityActive ? 1 : 0,
      appsRunningInBgCount: bgProcesses,
      backgroundServicesActiveCount: bgProcesses,
      appsRunningDuringIdleCount: idleHourApps,
      appInstallRatePerWeek: installRate,
      appUninstallRatePerWeek: 0,
      frequentInstallUninstallPattern: recentInstalls > 3,
      developerOptionsEnabled: devOptions,
      usbDebuggingEnabled: usbDebugging,
      unknownSourcesEnabled: unknownSources,
      batteryOptDisabledAppsCount: batteryOptDisabled,
      cpuUsagePercent: cpuUsage,
      cpuUsageWhenScreenOff: cpuWhenScreenOff,
      screenOnToUsageRatio: screenOnRatio,
      rootDetected: rootDetected,
      activeDeviceAdminCount: activeAdminCount,
      accessibilityServicesActive: accessibilityActive,
      memoryUsagePercent: memPct,
      batteryDrainRatePerHour: battDrain,
      bgDataSentMb: totalBgSentMb,
      bgDataReceivedMb: totalBgRecvMb,
      dataSentDuringIdleMb: idleSentMb,
      dataSentWithoutInteraction: dataSentNoInteraction,
      uniqueRemoteIpsCount: uniqueIps,
      frequentSmallPackets: smallPackets,
      cpuSpikesWhenScreenOff: cpuSpikesScreenOff,
      memoryUsageVariance: memVariance,
      maliciousConnectionCount: malCount,
      suspiciousConnectionCount: suspCount,
      dataSentWhenMicActive: micAndNet,
      dataSentWhenCameraActive: camAndNet,
      networkDuringSensorUsage: sensorAndNet,
      fgToBgActivityRatio: bgRatio,
      sensorToNetworkCorrelation: sensorNetCorrelation,
      overallIdleAnomalyScore: idleAnomaly,
    );
  }

  // ── Helpers ────────────────────────────────────────────────────────────

  bool _isIdleHour(int hour) => hour >= 23 || hour < 6;

  double _shannonEntropy(int active, int total) {
    if (active == 0 || total == 0) return 0;
    final p = active / total;
    final q = 1 - p;
    if (p == 0 || q == 0) return 0;
    return -(p * (log(p) / log(2)) + q * (log(q) / log(2)));
  }

  int _sumField(List<Map<String, dynamic>> apps, String field) {
    return apps.fold<int>(0, (s, a) {
      final v = a[field];
      if (v is List) return s + v.length;
      if (v is int) return s + v;
      return s;
    });
  }

  double _variance(List<double> values) {
    if (values.length < 2) return 0;
    final mean = values.reduce((a, b) => a + b) / values.length;
    final sq   = values.map((v) => pow(v - mean, 2)).reduce((a, b) => a + b);
    return sq / values.length;
  }

  double _computeBatteryDrain(double currentLevel, DateTime now) {
    if (currentLevel < 0) return 0;
    if (_lastBatteryLevel < 0 || _lastBatteryCheck == null) {
      _lastBatteryLevel = currentLevel;
      _lastBatteryCheck = now;
      return 0;
    }
    final elapsedHrs = now.difference(_lastBatteryCheck!).inMinutes / 60.0;
    if (elapsedHrs < 0.05) return 0; // less than 3 min — too early
    final drain = (_lastBatteryLevel - currentLevel) / elapsedHrs;
    _lastBatteryLevel = currentLevel;
    _lastBatteryCheck = now;
    return drain.clamp(0, 100);
  }

  double _computeScreenRatio(int totalFgMs) {
    // Approximate: a normal user has ~3–4h foreground time per day (10800000–14400000 ms)
    const normalFgMs = 10800000.0;
    if (totalFgMs <= 0) return 0;
    return (totalFgMs / normalFgMs).clamp(0.0, 5.0);
  }
}