/// DeviceFeatures — snapshot of all 60+ measurable signals on the device.
///
/// Every field maps directly to one of the features in the feature list.
/// All values are REAL — derived from Android APIs, not simulated.
///
/// Grouped into 6 categories matching the feature spec:
///   1. Sensor Behavior
///   2. Permission Behavior
///   3. App Behavior
///   4. System Behavior
///   5. Network & Resource
///   6. Final Aggregated
class DeviceFeatures {
  final DateTime collectedAt;

  // ═══════════════════════════════════════════════════════════════
  // 1. SENSOR BEHAVIOR FEATURES
  // ═══════════════════════════════════════════════════════════════

  // Camera
  final bool cameraActiveNow; // hardware-level: is camera open this instant
  final int
  cameraAppsWithPermission; // how many user apps have camera permission
  final int cameraAppsRecentFg; // subset that were in foreground recently
  final bool
  cameraActiveWhenScreenOff; // detected via CameraManager unavailability + screen state
  final bool cameraActiveDuringIdle; // active between 23:00–06:00

  // Microphone
  final bool
  micActiveNow; // hardware-level: AudioManager.getActiveRecordingConfigurations
  final int micAppsWithPermission; // how many user apps have mic permission
  final int micAppsRecentFg;
  final bool micActiveOutsideCalls; // active but no call in progress
  final bool micActiveWhenScreenOff;
  final bool micActiveDuringIdle;

  // Location
  final int locationAppsWithPermission;
  final int locationBgAppsCount; // apps with ACCESS_BACKGROUND_LOCATION
  final bool locationActiveDuringIdle;

  // Derived sensor metrics
  final double sensorActivityEntropy; // 0–1: how unpredictably sensors fire
  final double sensorUsageIrregularity; // 0–100: deviation from normal patterns

  // ═══════════════════════════════════════════════════════════════
  // 2. PERMISSION BEHAVIOR FEATURES
  // ═══════════════════════════════════════════════════════════════

  final int
  dangerousPermissionCount; // DANGEROUS-level permissions granted to user apps
  final int highRiskPermissionCount; // camera + mic + location + SMS + contacts
  final bool cameraPermissionGranted;
  final bool micPermissionGranted;
  final bool locationPermissionGranted;
  final bool bgLocationPermissionGranted;
  final bool
  accessibilityPermissionActive; // any app has accessibility service running
  final bool deviceAdminActive; // any app has device admin rights
  final double unusedButGrantedRatio; // granted but app not used in 7 days
  final double permissionsVsUsageMismatch; // 0–100 mismatch score

  // ═══════════════════════════════════════════════════════════════
  // 3. APP BEHAVIOR FEATURES
  // ═══════════════════════════════════════════════════════════════

  final int totalUserInstalledApps;
  final int nonPlayStoreAppCount; // sideloaded / unknown installer -- informational only,
  // see flaggedAppCount below for what actually drives the score
  final int recentlyInstalledAppCount; // installed in last 7 days
  final int unknownInstallerAppCount; // informational only, same reason
  // Apps the App Trust Engine's own evidence ladder already flagged NEEDS_REVIEW or worse --
  // i.e. sideloaded/unknown-installer AND showing some other concerning signal, not sideloaded
  // status alone. This is what the App Behavior score actually uses: a developer's own dozen
  // sideloaded test builds, or a device shipped with a dozen OEM-bundled apps, are not
  // evidence of a RAT by themselves (see AppTrustEngine's TRUSTED-baseline / evidence-ladder
  // docs) -- scoring the raw count punished exactly the false positives that engine exists
  // to avoid, just from the Dashboard side instead of the per-app side.
  final int flaggedAppCount;
  final int appsTargetingOldSdkCount; // targetSdk < 26 (pre-Oreo)
  final int appsWithAccessibilityCount;
  final int appsRunningInBgCount;
  final int backgroundServicesActiveCount;
  final int appsRunningDuringIdleCount; // had activity between 23:00–06:00
  final double appInstallRatePerWeek; // new installs / 7 days
  final double appUninstallRatePerWeek;
  final bool frequentInstallUninstallPattern; // install+uninstall same week

  // ═══════════════════════════════════════════════════════════════
  // 4. SYSTEM BEHAVIOR FEATURES
  // ═══════════════════════════════════════════════════════════════

  final bool developerOptionsEnabled;
  final bool usbDebuggingEnabled;
  final bool unknownSourcesEnabled; // install from unknown sources
  final bool verifyAppsDisabled; // Play Protect app-verification turned off
  final int batteryOptDisabledAppsCount; // apps ignoring battery optimization
  final double cpuUsagePercent; // current real CPU %
  final double cpuUsageWhenScreenOff; // approximated from idle readings
  final double screenOnToUsageRatio; // screen on time vs active app time
  final bool rootDetected;
  final int activeDeviceAdminCount;
  final bool accessibilityServicesActive;
  final double memoryUsagePercent;
  final double batteryDrainRatePerHour; // %/hr from BatteryManager

  // ═══════════════════════════════════════════════════════════════
  // 5. NETWORK & RESOURCE FEATURES
  // ═══════════════════════════════════════════════════════════════

  final double bgDataSentMb; // total background TX in MB
  final double bgDataReceivedMb; // total background RX in MB
  final double dataSentDuringIdleMb; // TX between 23:00–06:00
  final double dataSentWithoutInteraction; // TX when screen was off
  final int uniqueRemoteIpsCount; // distinct external IPs contacted
  final bool frequentSmallPackets; // many tiny uploads (C2C beacon pattern)
  final double cpuSpikesWhenScreenOff; // count of spikes during screen-off
  final double memoryUsageVariance; // stddev of memory readings
  final int maliciousConnectionCount;
  final int suspiciousConnectionCount;

  // Correlation features
  final bool dataSentWhenMicActive; // network TX detected while mic on
  final bool dataSentWhenCameraActive; // network TX detected while camera on
  final bool networkDuringSensorUsage; // combined: any sensor + network

  // ═══════════════════════════════════════════════════════════════
  // 6. FINAL AGGREGATED FEATURES
  // ═══════════════════════════════════════════════════════════════

  final double fgToBgActivityRatio; // foreground time / background time
  final double
  sensorToNetworkCorrelation; // 0–1: how much sensors fire with network
  final double overallIdleAnomalyScore; // 0–100: activity during idle hours

  const DeviceFeatures({
    required this.collectedAt,
    // Sensor
    required this.cameraActiveNow,
    required this.cameraAppsWithPermission,
    required this.cameraAppsRecentFg,
    required this.cameraActiveWhenScreenOff,
    required this.cameraActiveDuringIdle,
    required this.micActiveNow,
    required this.micAppsWithPermission,
    required this.micAppsRecentFg,
    required this.micActiveOutsideCalls,
    required this.micActiveWhenScreenOff,
    required this.micActiveDuringIdle,
    required this.locationAppsWithPermission,
    required this.locationBgAppsCount,
    required this.locationActiveDuringIdle,
    required this.sensorActivityEntropy,
    required this.sensorUsageIrregularity,
    // Permissions
    required this.dangerousPermissionCount,
    required this.highRiskPermissionCount,
    required this.cameraPermissionGranted,
    required this.micPermissionGranted,
    required this.locationPermissionGranted,
    required this.bgLocationPermissionGranted,
    required this.accessibilityPermissionActive,
    required this.deviceAdminActive,
    required this.unusedButGrantedRatio,
    required this.permissionsVsUsageMismatch,
    // App behavior
    required this.totalUserInstalledApps,
    required this.nonPlayStoreAppCount,
    required this.recentlyInstalledAppCount,
    required this.unknownInstallerAppCount,
    required this.flaggedAppCount,
    required this.appsTargetingOldSdkCount,
    required this.appsWithAccessibilityCount,
    required this.appsRunningInBgCount,
    required this.backgroundServicesActiveCount,
    required this.appsRunningDuringIdleCount,
    required this.appInstallRatePerWeek,
    required this.appUninstallRatePerWeek,
    required this.frequentInstallUninstallPattern,
    // System
    required this.developerOptionsEnabled,
    required this.usbDebuggingEnabled,
    required this.unknownSourcesEnabled,
    required this.verifyAppsDisabled,
    required this.batteryOptDisabledAppsCount,
    required this.cpuUsagePercent,
    required this.cpuUsageWhenScreenOff,
    required this.screenOnToUsageRatio,
    required this.rootDetected,
    required this.activeDeviceAdminCount,
    required this.accessibilityServicesActive,
    required this.memoryUsagePercent,
    required this.batteryDrainRatePerHour,
    // Network
    required this.bgDataSentMb,
    required this.bgDataReceivedMb,
    required this.dataSentDuringIdleMb,
    required this.dataSentWithoutInteraction,
    required this.uniqueRemoteIpsCount,
    required this.frequentSmallPackets,
    required this.cpuSpikesWhenScreenOff,
    required this.memoryUsageVariance,
    required this.maliciousConnectionCount,
    required this.suspiciousConnectionCount,
    required this.dataSentWhenMicActive,
    required this.dataSentWhenCameraActive,
    required this.networkDuringSensorUsage,
    // Aggregated
    required this.fgToBgActivityRatio,
    required this.sensorToNetworkCorrelation,
    required this.overallIdleAnomalyScore,
  });

  /// Empty baseline — all signals clean, used as initial state.
  factory DeviceFeatures.empty() => DeviceFeatures(
    collectedAt: DateTime.now(),
    cameraActiveNow: false,
    cameraAppsWithPermission: 0,
    cameraAppsRecentFg: 0,
    cameraActiveWhenScreenOff: false,
    cameraActiveDuringIdle: false,
    micActiveNow: false,
    micAppsWithPermission: 0,
    micAppsRecentFg: 0,
    micActiveOutsideCalls: false,
    micActiveWhenScreenOff: false,
    micActiveDuringIdle: false,
    locationAppsWithPermission: 0,
    locationBgAppsCount: 0,
    locationActiveDuringIdle: false,
    sensorActivityEntropy: 0,
    sensorUsageIrregularity: 0,
    dangerousPermissionCount: 0,
    highRiskPermissionCount: 0,
    cameraPermissionGranted: false,
    micPermissionGranted: false,
    locationPermissionGranted: false,
    bgLocationPermissionGranted: false,
    accessibilityPermissionActive: false,
    deviceAdminActive: false,
    unusedButGrantedRatio: 0,
    permissionsVsUsageMismatch: 0,
    totalUserInstalledApps: 0,
    nonPlayStoreAppCount: 0,
    recentlyInstalledAppCount: 0,
    unknownInstallerAppCount: 0,
    flaggedAppCount: 0,
    appsTargetingOldSdkCount: 0,
    appsWithAccessibilityCount: 0,
    appsRunningInBgCount: 0,
    backgroundServicesActiveCount: 0,
    appsRunningDuringIdleCount: 0,
    appInstallRatePerWeek: 0,
    appUninstallRatePerWeek: 0,
    frequentInstallUninstallPattern: false,
    developerOptionsEnabled: false,
    usbDebuggingEnabled: false,
    unknownSourcesEnabled: false,
    verifyAppsDisabled: false,
    batteryOptDisabledAppsCount: 0,
    cpuUsagePercent: 0,
    cpuUsageWhenScreenOff: 0,
    screenOnToUsageRatio: 1.0,
    rootDetected: false,
    activeDeviceAdminCount: 0,
    accessibilityServicesActive: false,
    memoryUsagePercent: 0,
    batteryDrainRatePerHour: 0,
    bgDataSentMb: 0,
    bgDataReceivedMb: 0,
    dataSentDuringIdleMb: 0,
    dataSentWithoutInteraction: 0,
    uniqueRemoteIpsCount: 0,
    frequentSmallPackets: false,
    cpuSpikesWhenScreenOff: 0,
    memoryUsageVariance: 0,
    maliciousConnectionCount: 0,
    suspiciousConnectionCount: 0,
    dataSentWhenMicActive: false,
    dataSentWhenCameraActive: false,
    networkDuringSensorUsage: false,
    fgToBgActivityRatio: 1.0,
    sensorToNetworkCorrelation: 0,
    overallIdleAnomalyScore: 0,
  );

  /// Returns a copy with the given fields replaced. Used to build focused
  /// test fixtures off `DeviceFeatures.empty()` without repeating all ~65
  /// constructor arguments per scenario.
  DeviceFeatures copyWith({
    DateTime? collectedAt,
    bool? cameraActiveNow,
    int? cameraAppsWithPermission,
    int? cameraAppsRecentFg,
    bool? cameraActiveWhenScreenOff,
    bool? cameraActiveDuringIdle,
    bool? micActiveNow,
    int? micAppsWithPermission,
    int? micAppsRecentFg,
    bool? micActiveOutsideCalls,
    bool? micActiveWhenScreenOff,
    bool? micActiveDuringIdle,
    int? locationAppsWithPermission,
    int? locationBgAppsCount,
    bool? locationActiveDuringIdle,
    double? sensorActivityEntropy,
    double? sensorUsageIrregularity,
    int? dangerousPermissionCount,
    int? highRiskPermissionCount,
    bool? cameraPermissionGranted,
    bool? micPermissionGranted,
    bool? locationPermissionGranted,
    bool? bgLocationPermissionGranted,
    bool? accessibilityPermissionActive,
    bool? deviceAdminActive,
    double? unusedButGrantedRatio,
    double? permissionsVsUsageMismatch,
    int? totalUserInstalledApps,
    int? nonPlayStoreAppCount,
    int? recentlyInstalledAppCount,
    int? unknownInstallerAppCount,
    int? flaggedAppCount,
    int? appsTargetingOldSdkCount,
    int? appsWithAccessibilityCount,
    int? appsRunningInBgCount,
    int? backgroundServicesActiveCount,
    int? appsRunningDuringIdleCount,
    double? appInstallRatePerWeek,
    double? appUninstallRatePerWeek,
    bool? frequentInstallUninstallPattern,
    bool? developerOptionsEnabled,
    bool? usbDebuggingEnabled,
    bool? unknownSourcesEnabled,
    bool? verifyAppsDisabled,
    int? batteryOptDisabledAppsCount,
    double? cpuUsagePercent,
    double? cpuUsageWhenScreenOff,
    double? screenOnToUsageRatio,
    bool? rootDetected,
    int? activeDeviceAdminCount,
    bool? accessibilityServicesActive,
    double? memoryUsagePercent,
    double? batteryDrainRatePerHour,
    double? bgDataSentMb,
    double? bgDataReceivedMb,
    double? dataSentDuringIdleMb,
    double? dataSentWithoutInteraction,
    int? uniqueRemoteIpsCount,
    bool? frequentSmallPackets,
    double? cpuSpikesWhenScreenOff,
    double? memoryUsageVariance,
    int? maliciousConnectionCount,
    int? suspiciousConnectionCount,
    bool? dataSentWhenMicActive,
    bool? dataSentWhenCameraActive,
    bool? networkDuringSensorUsage,
    double? fgToBgActivityRatio,
    double? sensorToNetworkCorrelation,
    double? overallIdleAnomalyScore,
  }) => DeviceFeatures(
    collectedAt: collectedAt ?? this.collectedAt,
    cameraActiveNow: cameraActiveNow ?? this.cameraActiveNow,
    cameraAppsWithPermission:
        cameraAppsWithPermission ?? this.cameraAppsWithPermission,
    cameraAppsRecentFg: cameraAppsRecentFg ?? this.cameraAppsRecentFg,
    cameraActiveWhenScreenOff:
        cameraActiveWhenScreenOff ?? this.cameraActiveWhenScreenOff,
    cameraActiveDuringIdle:
        cameraActiveDuringIdle ?? this.cameraActiveDuringIdle,
    micActiveNow: micActiveNow ?? this.micActiveNow,
    micAppsWithPermission: micAppsWithPermission ?? this.micAppsWithPermission,
    micAppsRecentFg: micAppsRecentFg ?? this.micAppsRecentFg,
    micActiveOutsideCalls: micActiveOutsideCalls ?? this.micActiveOutsideCalls,
    micActiveWhenScreenOff:
        micActiveWhenScreenOff ?? this.micActiveWhenScreenOff,
    micActiveDuringIdle: micActiveDuringIdle ?? this.micActiveDuringIdle,
    locationAppsWithPermission:
        locationAppsWithPermission ?? this.locationAppsWithPermission,
    locationBgAppsCount: locationBgAppsCount ?? this.locationBgAppsCount,
    locationActiveDuringIdle:
        locationActiveDuringIdle ?? this.locationActiveDuringIdle,
    sensorActivityEntropy: sensorActivityEntropy ?? this.sensorActivityEntropy,
    sensorUsageIrregularity:
        sensorUsageIrregularity ?? this.sensorUsageIrregularity,
    dangerousPermissionCount:
        dangerousPermissionCount ?? this.dangerousPermissionCount,
    highRiskPermissionCount:
        highRiskPermissionCount ?? this.highRiskPermissionCount,
    cameraPermissionGranted:
        cameraPermissionGranted ?? this.cameraPermissionGranted,
    micPermissionGranted: micPermissionGranted ?? this.micPermissionGranted,
    locationPermissionGranted:
        locationPermissionGranted ?? this.locationPermissionGranted,
    bgLocationPermissionGranted:
        bgLocationPermissionGranted ?? this.bgLocationPermissionGranted,
    accessibilityPermissionActive:
        accessibilityPermissionActive ?? this.accessibilityPermissionActive,
    deviceAdminActive: deviceAdminActive ?? this.deviceAdminActive,
    unusedButGrantedRatio:
        unusedButGrantedRatio ?? this.unusedButGrantedRatio,
    permissionsVsUsageMismatch:
        permissionsVsUsageMismatch ?? this.permissionsVsUsageMismatch,
    totalUserInstalledApps:
        totalUserInstalledApps ?? this.totalUserInstalledApps,
    nonPlayStoreAppCount: nonPlayStoreAppCount ?? this.nonPlayStoreAppCount,
    recentlyInstalledAppCount:
        recentlyInstalledAppCount ?? this.recentlyInstalledAppCount,
    unknownInstallerAppCount:
        unknownInstallerAppCount ?? this.unknownInstallerAppCount,
    flaggedAppCount: flaggedAppCount ?? this.flaggedAppCount,
    appsTargetingOldSdkCount:
        appsTargetingOldSdkCount ?? this.appsTargetingOldSdkCount,
    appsWithAccessibilityCount:
        appsWithAccessibilityCount ?? this.appsWithAccessibilityCount,
    appsRunningInBgCount: appsRunningInBgCount ?? this.appsRunningInBgCount,
    backgroundServicesActiveCount:
        backgroundServicesActiveCount ?? this.backgroundServicesActiveCount,
    appsRunningDuringIdleCount:
        appsRunningDuringIdleCount ?? this.appsRunningDuringIdleCount,
    appInstallRatePerWeek: appInstallRatePerWeek ?? this.appInstallRatePerWeek,
    appUninstallRatePerWeek:
        appUninstallRatePerWeek ?? this.appUninstallRatePerWeek,
    frequentInstallUninstallPattern:
        frequentInstallUninstallPattern ?? this.frequentInstallUninstallPattern,
    developerOptionsEnabled:
        developerOptionsEnabled ?? this.developerOptionsEnabled,
    usbDebuggingEnabled: usbDebuggingEnabled ?? this.usbDebuggingEnabled,
    unknownSourcesEnabled: unknownSourcesEnabled ?? this.unknownSourcesEnabled,
    verifyAppsDisabled: verifyAppsDisabled ?? this.verifyAppsDisabled,
    batteryOptDisabledAppsCount:
        batteryOptDisabledAppsCount ?? this.batteryOptDisabledAppsCount,
    cpuUsagePercent: cpuUsagePercent ?? this.cpuUsagePercent,
    cpuUsageWhenScreenOff: cpuUsageWhenScreenOff ?? this.cpuUsageWhenScreenOff,
    screenOnToUsageRatio: screenOnToUsageRatio ?? this.screenOnToUsageRatio,
    rootDetected: rootDetected ?? this.rootDetected,
    activeDeviceAdminCount:
        activeDeviceAdminCount ?? this.activeDeviceAdminCount,
    accessibilityServicesActive:
        accessibilityServicesActive ?? this.accessibilityServicesActive,
    memoryUsagePercent: memoryUsagePercent ?? this.memoryUsagePercent,
    batteryDrainRatePerHour:
        batteryDrainRatePerHour ?? this.batteryDrainRatePerHour,
    bgDataSentMb: bgDataSentMb ?? this.bgDataSentMb,
    bgDataReceivedMb: bgDataReceivedMb ?? this.bgDataReceivedMb,
    dataSentDuringIdleMb: dataSentDuringIdleMb ?? this.dataSentDuringIdleMb,
    dataSentWithoutInteraction:
        dataSentWithoutInteraction ?? this.dataSentWithoutInteraction,
    uniqueRemoteIpsCount: uniqueRemoteIpsCount ?? this.uniqueRemoteIpsCount,
    frequentSmallPackets: frequentSmallPackets ?? this.frequentSmallPackets,
    cpuSpikesWhenScreenOff:
        cpuSpikesWhenScreenOff ?? this.cpuSpikesWhenScreenOff,
    memoryUsageVariance: memoryUsageVariance ?? this.memoryUsageVariance,
    maliciousConnectionCount:
        maliciousConnectionCount ?? this.maliciousConnectionCount,
    suspiciousConnectionCount:
        suspiciousConnectionCount ?? this.suspiciousConnectionCount,
    dataSentWhenMicActive: dataSentWhenMicActive ?? this.dataSentWhenMicActive,
    dataSentWhenCameraActive:
        dataSentWhenCameraActive ?? this.dataSentWhenCameraActive,
    networkDuringSensorUsage:
        networkDuringSensorUsage ?? this.networkDuringSensorUsage,
    fgToBgActivityRatio: fgToBgActivityRatio ?? this.fgToBgActivityRatio,
    sensorToNetworkCorrelation:
        sensorToNetworkCorrelation ?? this.sensorToNetworkCorrelation,
    overallIdleAnomalyScore:
        overallIdleAnomalyScore ?? this.overallIdleAnomalyScore,
  );

  /// Summary string for logging.
  String get summary =>
      'cam=$cameraActiveNow mic=$micActiveNow '
      'root=$rootDetected usbDbg=$usbDebuggingEnabled '
      'sideloaded=$nonPlayStoreAppCount flagged=$flaggedAppCount '
      'malicious=$maliciousConnectionCount suspicious=$suspiciousConnectionCount '
      'cpu=${cpuUsagePercent.toStringAsFixed(1)}% '
      'bgData=${bgDataSentMb.toStringAsFixed(2)}MB';
}
