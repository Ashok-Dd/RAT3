import 'package:flutter_test/flutter_test.dart';
import 'package:rat3/data/models/app_models.dart';

/// Guards the JSON contract between MainActivity.handleScanAllApps (Kotlin) and
/// ScannedApp.fromMap (Dart). The actual evidence/trust-level correlation is
/// tested directly in Kotlin (AppTrustEngineTest) since that's where it runs —
/// this just proves the wire format round-trips correctly.
void main() {
  Map<String, dynamic> rawApp({
    String trustLevel = 'TRUSTED',
    List<String> evidence = const [],
    List<String> privateDataAccess = const [],
  }) => {
    'packageName': 'com.example.app',
    'appName': 'Example',
    'isSystemApp': false,
    'installSource': 'play_store',
    'isSideloaded': false,
    'firstInstallTime': 1000,
    'lastUpdateTime': 2000,
    'installDaysAgo': 400,
    'isRecentInstall': false,
    'versionName': '1.0',
    'targetSdkVersion': 34,
    'allPermissions': <String>['android.permission.INTERNET'],
    'dangerousGranted': <String>['android.permission.CAMERA'],
    'txBytes': 1024,
    'rxBytes': 2048,
    'backgroundTimeHrs': 1.5,
    'isCurrentlyRunning': false,
    'trustLevel': trustLevel,
    'trustReason': 'Trusted — installed from Play Store',
    'evidence': evidence,
    'privateDataAccess': privateDataAccess,
  };

  group('ScannedApp.fromMap', () {
    test('parses every AppTrustLevel value from the Kotlin wire format', () {
      final cases = {
        'TRUSTED': AppTrustLevel.trusted,
        'NEEDS_REVIEW': AppTrustLevel.needsReview,
        'SUSPICIOUS': AppTrustLevel.suspicious,
        'MALICIOUS_INDICATORS': AppTrustLevel.maliciousIndicators,
        'UNKNOWN': AppTrustLevel.unknown,
        'something_unexpected': AppTrustLevel.unknown,
      };
      for (final entry in cases.entries) {
        final app = ScannedApp.fromMap(rawApp(trustLevel: entry.key));
        expect(app.trustLevel, entry.value, reason: 'for "${entry.key}"');
      }
    });

    test('carries evidence and privateDataAccess through untouched', () {
      final app = ScannedApp.fromMap(
        rawApp(
          trustLevel: 'SUSPICIOUS',
          evidence: ['Can read your SMS messages', 'Installed 2 day(s) ago'],
          privateDataAccess: ['Can read SMS messages'],
        ),
      );
      expect(app.evidence, [
        'Can read your SMS messages',
        'Installed 2 day(s) ago',
      ]);
      expect(app.privateDataAccess, ['Can read SMS messages']);
    });

    test('a trusted app has empty evidence', () {
      final app = ScannedApp.fromMap(rawApp());
      expect(app.trustLevel, AppTrustLevel.trusted);
      expect(app.evidence, isEmpty);
    });

    test('missing evidence/privateDataAccess default to empty lists', () {
      final raw = rawApp()
        ..remove('evidence')
        ..remove('privateDataAccess');
      final app = ScannedApp.fromMap(raw);
      expect(app.evidence, isEmpty);
      expect(app.privateDataAccess, isEmpty);
    });

    test('numeric fields survive as num from the platform channel', () {
      final app = ScannedApp.fromMap(rawApp());
      expect(app.txBytes, 1024);
      expect(app.rxBytes, 2048);
      expect(app.backgroundTimeHrs, 1.5);
    });
  });
}
