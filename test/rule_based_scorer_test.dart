import 'package:flutter_test/flutter_test.dart';
import 'package:rat3/core/constants/app_constants.dart';
import 'package:rat3/layers/feature_engine/device_features.dart';
import 'package:rat3/layers/feature_engine/rule_based_scorer.dart';

void main() {
  final scorer = RuleBasedScorer();
  final clean = DeviceFeatures.empty();

  group('clean baseline', () {
    test('an all-clear feature set scores 0 with no triggered rules', () {
      final result = scorer.score(clean);
      expect(result.composite, 0);
      expect(result.triggeredRules, isEmpty);
    });
  });

  group('system security', () {
    test('rooted device triggers a critical rule and a non-zero system score', () {
      final result = scorer.score(clean.copyWith(rootDetected: true));
      final hit = result.triggeredRules.singleWhere(
        (h) => h.title == 'Device is rooted',
      );
      expect(hit.severity, AlertSeverity.critical);
      expect(result.systemScore, greaterThan(0));
      expect(result.composite, greaterThan(0));
    });

    test(
      'USB debugging alone triggers nothing -- a developer/poweruser setting, not risk',
      () {
        final result = scorer.score(
          clean.copyWith(usbDebuggingEnabled: true),
        );
        expect(result.triggeredRules, isEmpty);
        expect(result.systemScore, 0);
      },
    );

    test('developer options alone triggers nothing', () {
      final result = scorer.score(
        clean.copyWith(developerOptionsEnabled: true),
      );
      expect(result.triggeredRules, isEmpty);
      expect(result.systemScore, 0);
    });

    test(
      'root + USB debugging together is named specifically, beyond root alone',
      () {
        final rootOnly = scorer.score(clean.copyWith(rootDetected: true));
        final rootAndUsb = scorer.score(
          clean.copyWith(rootDetected: true, usbDebuggingEnabled: true),
        );
        expect(
          rootAndUsb.triggeredRules.any(
            (h) => h.title == 'Rooted device with USB debugging enabled',
          ),
          isTrue,
        );
        expect(rootAndUsb.systemScore, greaterThan(rootOnly.systemScore));
      },
    );

    test(
      'unknown sources alone triggers nothing -- only matters with a flagged app present',
      () {
        final alone = scorer.score(
          clean.copyWith(unknownSourcesEnabled: true),
        );
        expect(alone.triggeredRules, isEmpty);

        final withFlaggedApp = scorer.score(
          clean.copyWith(unknownSourcesEnabled: true, flaggedAppCount: 1),
        );
        expect(withFlaggedApp.triggeredRules, isNotEmpty);
      },
    );
  });

  group('app behavior', () {
    test(
      'a pile of sideloaded apps with nothing else notable scores nothing -- '
      'the App Trust Engine already cleared them',
      () {
        // e.g. a device shipped with a dozen OEM-bundled apps, or a developer with a
        // dozen of their own sideloaded test builds -- neither is evidence of a RAT.
        final result = scorer.score(
          clean.copyWith(nonPlayStoreAppCount: 12, unknownInstallerAppCount: 12),
        );
        expect(result.triggeredRules, isEmpty);
        expect(result.appScore, 0);
      },
    );

    test(
      'apps the App Trust Engine actually flagged do score, scaling with count',
      () {
        final one = scorer.score(clean.copyWith(flaggedAppCount: 1));
        final three = scorer.score(clean.copyWith(flaggedAppCount: 3));
        expect(one.triggeredRules, isNotEmpty);
        expect(three.appScore, greaterThan(one.appScore));
      },
    );
  });

  group('sensor behavior', () {
    test('camera active during idle hours is critical', () {
      final result = scorer.score(
        clean.copyWith(cameraActiveDuringIdle: true),
      );
      final hit = result.triggeredRules.singleWhere(
        (h) => h.title == 'Camera active during idle hours',
      );
      expect(hit.severity, AlertSeverity.critical);
      expect(result.sensorScore, greaterThan(0));
    });

    test('camera active right now is high, not critical', () {
      final result = scorer.score(clean.copyWith(cameraActiveNow: true));
      final hit = result.triggeredRules.singleWhere(
        (h) => h.title == 'Camera is in use right now',
      );
      expect(hit.severity, AlertSeverity.high);
    });

    test('network active during sensor usage is a critical correlation rule', () {
      final result = scorer.score(
        clean.copyWith(networkDuringSensorUsage: true),
      );
      final hit = result.triggeredRules.singleWhere(
        (h) => h.title == 'Network active during sensor usage',
      );
      expect(hit.severity, AlertSeverity.critical);
    });
  });

  group('aggregated correlations', () {
    test('strong sensor-network correlation (>0.6) is critical', () {
      final result = scorer.score(
        clean.copyWith(sensorToNetworkCorrelation: 0.75),
      );
      final hit = result.triggeredRules.singleWhere(
        (h) => h.title == 'Strong sensor–network correlation detected',
      );
      expect(hit.severity, AlertSeverity.critical);
      expect(result.aggregatedScore, greaterThanOrEqualTo(50));
    });

    test('moderate correlation (0.3–0.6) is high, not critical', () {
      final result = scorer.score(
        clean.copyWith(sensorToNetworkCorrelation: 0.45),
      );
      final hit = result.triggeredRules.singleWhere(
        (h) => h.title == 'Moderate sensor–network correlation',
      );
      expect(hit.severity, AlertSeverity.high);
    });

    test('correlation at or below 0.3 triggers nothing', () {
      final result = scorer.score(
        clean.copyWith(sensorToNetworkCorrelation: 0.3),
      );
      expect(result.aggregatedScore, 0);
    });
  });

  group('composite weighting', () {
    test('highPriorityRules only includes high and critical severities', () {
      final result = scorer.score(
        clean.copyWith(
          rootDetected: true, // critical
          developerOptionsEnabled: true, // low
        ),
      );
      expect(
        result.highPriorityRules.every(
          (h) => h.severity.index >= AlertSeverity.high.index,
        ),
        isTrue,
      );
      expect(
        result.highPriorityRules.any((h) => h.title == 'Device is rooted'),
        isTrue,
      );
      expect(
        result.highPriorityRules.any(
          (h) => h.title == 'Developer options are enabled',
        ),
        isFalse,
      );
    });

    test('multiple triggered categories combine into a higher composite '
        'than any single category alone', () {
      final rootOnly = scorer.score(clean.copyWith(rootDetected: true));
      final rootPlusNetwork = scorer.score(
        clean.copyWith(rootDetected: true, maliciousConnectionCount: 2),
      );
      expect(rootPlusNetwork.composite, greaterThan(rootOnly.composite));
    });

    test('composite is always clamped to 0-100', () {
      final worstCase = clean.copyWith(
        rootDetected: true,
        usbDebuggingEnabled: true,
        unknownSourcesEnabled: true,
        activeDeviceAdminCount: 3,
        accessibilityServicesActive: true,
        cpuUsagePercent: 99,
        memoryUsagePercent: 99,
        batteryOptDisabledAppsCount: 10,
        cameraActiveNow: true,
        micActiveNow: true,
        cameraActiveDuringIdle: true,
        micActiveDuringIdle: true,
        cameraActiveWhenScreenOff: true,
        micActiveWhenScreenOff: true,
        locationBgAppsCount: 5,
        locationActiveDuringIdle: true,
        sensorUsageIrregularity: 90,
        networkDuringSensorUsage: true,
        maliciousConnectionCount: 5,
        suspiciousConnectionCount: 5,
        bgDataSentMb: 100,
        dataSentDuringIdleMb: 50,
        dataSentWithoutInteraction: 50,
        uniqueRemoteIpsCount: 50,
        frequentSmallPackets: true,
        dataSentWhenMicActive: true,
        dataSentWhenCameraActive: true,
        nonPlayStoreAppCount: 5,
        unknownInstallerAppCount: 5,
        flaggedAppCount: 5,
        recentlyInstalledAppCount: 5,
        frequentInstallUninstallPattern: true,
        appsWithAccessibilityCount: 3,
        highRiskPermissionCount: 15,
        dangerousPermissionCount: 30,
        unusedButGrantedRatio: 0.9,
        permissionsVsUsageMismatch: 90,
        bgLocationPermissionGranted: true,
        deviceAdminActive: true,
        accessibilityPermissionActive: true,
        sensorToNetworkCorrelation: 0.9,
        overallIdleAnomalyScore: 90,
        fgToBgActivityRatio: 0.1,
        sensorActivityEntropy: 0.95,
      );
      final result = scorer.score(worstCase);
      expect(result.composite, lessThanOrEqualTo(100));
      expect(result.composite, greaterThan(80));
    });
  });
}
