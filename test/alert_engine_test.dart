import 'package:flutter_test/flutter_test.dart';
import 'package:rat3/core/constants/app_constants.dart';
import 'package:rat3/data/models/app_models.dart';
import 'package:rat3/data/services/notification_service.dart';
import 'package:rat3/data/services/storage_service.dart';
import 'package:rat3/layers/alert_engine/alert_engine.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Records every alert it would have pushed as an OS notification, without
/// touching the flutter_local_notifications plugin (no platform channel —
/// safe to run in a plain `flutter test`).
class _RecordingNotificationService extends NotificationService {
  final List<AlertEvent> shown = [];

  @override
  Future<void> showAlertNotification(AlertEvent alert) async {
    shown.add(alert);
  }
}

AlertEvent _alert({
  required String id,
  AlertSeverity severity = AlertSeverity.high,
  String title = 'Test Alert',
  bool notify = true,
  String source = 'Test',
}) => AlertEvent(
  id: id,
  severity: severity,
  title: title,
  description: 'desc',
  userFriendlyMessage: 'message',
  timestamp: DateTime.now(),
  source: source,
  notify: notify,
);

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late _RecordingNotificationService notifications;
  late AlertEngine engine;

  setUp(() async {
    SharedPreferences.setMockInitialValues({});
    final storage = StorageService();
    await storage.init();
    notifications = _RecordingNotificationService();
    engine = AlertEngine(
      notificationService: notifications,
      storageService: storage,
    );
    engine.init();
  });

  tearDown(() {
    engine.dispose();
  });

  group('Tier 1 — id dedup', () {
    test('the same alert id is never shown twice in a session', () {
      engine.injectAlert(_alert(id: 'a1'));
      engine.injectAlert(_alert(id: 'a1'));
      expect(engine.allAlerts.length, 1);
    });
  });

  group('Tier 2 — title + cooldown dedup', () {
    test('same title within the cooldown window is suppressed even with a '
        'different id', () {
      engine.injectAlert(
        _alert(id: 'a1', title: 'Same Title', severity: AlertSeverity.critical),
      );
      engine.injectAlert(
        _alert(id: 'a2', title: 'Same Title', severity: AlertSeverity.critical),
      );
      expect(engine.allAlerts.length, 1);
    });

    test('different titles are not suppressed by each other', () {
      engine.injectAlert(_alert(id: 'a1', title: 'Title A'));
      engine.injectAlert(_alert(id: 'a2', title: 'Title B'));
      expect(engine.allAlerts.length, 2);
    });
  });

  group('Tier 3 — app-scan reset', () {
    test('resetForNewScan clears only App Scanner alerts, keeps device-state '
        'alerts', () async {
      engine.injectAlert(
        _alert(id: 'device_rooted', source: 'Runtime Monitor', title: 'Rooted'),
      );
      engine.injectAlert(
        _alert(id: 'appscan_x', source: 'App Scanner', title: 'App Finding'),
      );
      expect(engine.allAlerts.length, 2);

      await engine.resetForNewScan();

      expect(engine.allAlerts.length, 1);
      expect(engine.allAlerts.single.source, 'Runtime Monitor');
    });

    test('injectAppScanAlerts replaces the previous app-scan batch', () async {
      engine.injectAppScanAlerts([
        _alert(id: 'appscan_1', source: 'App Scanner', title: 'First'),
      ]);
      expect(engine.allAlerts.length, 1);

      engine.injectAppScanAlerts([
        _alert(id: 'appscan_2', source: 'App Scanner', title: 'Second'),
      ]);
      expect(engine.allAlerts.length, 1);
      expect(engine.allAlerts.single.id, 'appscan_2');
    });
  });

  group('notify suppression (fix for duplicate OS notifications)', () {
    test('notify:false alerts are recorded but never pushed', () {
      engine.injectAlert(
        _alert(id: 'silent1', notify: false, severity: AlertSeverity.critical),
      );
      expect(engine.allAlerts.length, 1);
      expect(notifications.shown, isEmpty);
    });

    test('notify:true at medium+ severity IS pushed', () {
      engine.injectAlert(
        _alert(id: 'loud1', notify: true, severity: AlertSeverity.high),
      );
      expect(notifications.shown.length, 1);
      expect(notifications.shown.single.id, 'loud1');
    });

    test('low severity is never pushed regardless of notify', () {
      engine.injectAlert(
        _alert(id: 'low1', notify: true, severity: AlertSeverity.low),
      );
      expect(notifications.shown, isEmpty);
    });
  });

  group('criticalCount', () {
    test('counts critical and high severities only', () {
      engine.injectAlert(
        _alert(id: 'c1', severity: AlertSeverity.critical, title: 'C'),
      );
      engine.injectAlert(
        _alert(id: 'h1', severity: AlertSeverity.high, title: 'H'),
      );
      engine.injectAlert(
        _alert(id: 'l1', severity: AlertSeverity.low, title: 'L'),
      );
      expect(engine.criticalCount, 2);
    });
  });

  group('clearAlerts', () {
    test(
      'removes everything and lets a previously-suppressed id fire again',
      () async {
        engine.injectAlert(_alert(id: 'a1', title: 'T1'));
        engine.injectAlert(_alert(id: 'a1', title: 'T1')); // suppressed dup
        expect(engine.allAlerts.length, 1);

        await engine.clearAlerts();
        expect(engine.allAlerts, isEmpty);

        engine.injectAlert(_alert(id: 'a1', title: 'T1'));
        expect(engine.allAlerts.length, 1);
      },
    );
  });
}
