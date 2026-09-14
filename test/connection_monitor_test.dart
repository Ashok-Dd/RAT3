import 'package:flutter_test/flutter_test.dart';
import 'package:rat3/data/models/app_models.dart';
import 'package:rat3/data/services/platform_channel_service.dart';
import 'package:rat3/layers/connection_monitor/connection_monitor.dart';

/// A fake PlatformChannelService that never touches a real MethodChannel —
/// startVpnMonitor always "succeeds" and getActiveConnections returns
/// whatever the test queues up, so ConnectionMonitor's correlation logic
/// (the actual thing worth testing) can run without a device.
class _FakePlatform extends PlatformChannelService {
  List<Map<String, dynamic>> nextConnections = [];

  @override
  Future<bool> startVpnMonitor() async => true;

  @override
  Future<void> stopVpnMonitor() async {}

  @override
  Future<bool> isVpnMonitorActive() async => true;

  @override
  Future<List<Map<String, dynamic>>> getActiveConnections() async =>
      nextConnections;
}

Map<String, dynamic> _conn({
  String protocol = 'TCP',
  String packageName = 'com.example.app',
  String appName = 'Example',
  String remoteAddress = '93.184.216.34',
  int remotePort = 443,
  int reconnectCount = 0,
  DateTime? firstSeen,
  DateTime? lastSeen,
  bool isActive = true,
  String? queriedDomain,
}) {
  final now = DateTime.now();
  return {
    'protocol': protocol,
    'packageName': packageName,
    'appName': appName,
    'remoteAddress': remoteAddress,
    'remotePort': remotePort,
    'firstSeenMs': (firstSeen ?? now).millisecondsSinceEpoch,
    'lastSeenMs': (lastSeen ?? now).millisecondsSinceEpoch,
    'bytesSent': 1024,
    'bytesReceived': 4096,
    'packetCount': 5,
    'reconnectCount': reconnectCount,
    'isActive': isActive,
    'queriedDomain': queriedDomain,
  };
}

void main() {
  late _FakePlatform platform;
  late ConnectionMonitor monitor;

  setUp(() {
    platform = _FakePlatform();
    monitor = ConnectionMonitor(platform: platform);
  });

  tearDown(() => monitor.dispose());

  test('a single ordinary connection from a trusted app is NORMAL', () async {
    platform.nextConnections = [_conn()];
    await monitor.enable();
    await Future<void>.delayed(Duration.zero);

    final snapshot = monitor.lastSnapshot;
    expect(snapshot, hasLength(1));
    expect(snapshot.single.assessment, ConnectionAssessment.normal);
    expect(snapshot.single.reasons, isEmpty);
  });

  test('a persistent connection alone is only INVESTIGATE, not SUSPICIOUS', () async {
    platform.nextConnections = [
      _conn(
        reconnectCount: 3,
        firstSeen: DateTime.now().subtract(const Duration(minutes: 5)),
      ),
    ];
    await monitor.enable();
    await Future<void>.delayed(Duration.zero);

    expect(monitor.lastSnapshot.single.assessment, ConnectionAssessment.investigate);
  });

  test('a persistent connection to a known suspicious port is SUSPICIOUS', () async {
    platform.nextConnections = [
      _conn(
        remotePort: 4444, // in AppConstants.suspiciousPorts
        reconnectCount: 3,
        firstSeen: DateTime.now().subtract(const Duration(minutes: 5)),
      ),
    ];
    await monitor.enable();
    await Future<void>.delayed(Duration.zero);

    final c = monitor.lastSnapshot.single;
    expect(c.assessment, ConnectionAssessment.suspicious);
    expect(c.reasons.length, greaterThanOrEqualTo(2));
  });

  test(
    'a connection from an app the App Trust Engine already flagged needs only one more signal to become SUSPICIOUS',
    () async {
      monitor.untrustedPackages = {'com.example.app'};
      platform.nextConnections = [
        _conn(
          reconnectCount: 3,
          firstSeen: DateTime.now().subtract(const Duration(minutes: 5)),
        ),
      ];
      await monitor.enable();
      await Future<void>.delayed(Duration.zero);

      final c = monitor.lastSnapshot.single;
      expect(c.assessment, ConnectionAssessment.suspicious);
      expect(c.reasons.any((r) => r.contains('unresolved security findings')), isTrue);
    },
  );

  test('a known-malicious IP prefix match alone is only INVESTIGATE', () async {
    platform.nextConnections = [_conn(remoteAddress: '185.220.1.1')];
    await monitor.enable();
    await Future<void>.delayed(Duration.zero);

    expect(monitor.lastSnapshot.single.assessment, ConnectionAssessment.investigate);
  });

  test(
    'a DGA-looking queried domain alone is only INVESTIGATE, not SUSPICIOUS',
    () async {
      platform.nextConnections = [
        _conn(remotePort: 53, queriedDomain: 'xqzptkvwmrfjhbsd.com'),
      ];
      await monitor.enable();
      await Future<void>.delayed(Duration.zero);

      final c = monitor.lastSnapshot.single;
      expect(c.assessment, ConnectionAssessment.investigate);
      expect(c.reasons.any((r) => r.contains('algorithmically-generated')), isTrue);
    },
  );

  test(
    'a DGA-looking domain plus a suspicious port together are SUSPICIOUS',
    () async {
      platform.nextConnections = [
        _conn(remotePort: 4444, queriedDomain: 'xqzptkvwmrfjhbsd.net'),
      ];
      await monitor.enable();
      await Future<void>.delayed(Duration.zero);

      expect(monitor.lastSnapshot.single.assessment, ConnectionAssessment.suspicious);
    },
  );

  test('an ordinary-looking domain contributes no signal', () async {
    platform.nextConnections = [
      _conn(remotePort: 53, queriedDomain: 'www.google.com'),
    ];
    await monitor.enable();
    await Future<void>.delayed(Duration.zero);

    expect(monitor.lastSnapshot.single.assessment, ConnectionAssessment.normal);
  });

  group('looksAlgorithmicallyGenerated', () {
    test('flags a long, high-entropy random-looking label', () {
      expect(looksAlgorithmicallyGenerated('xqzptkvwmrfjhbsd.com'), isTrue);
    });

    test('flags a long run of consonants with no vowels', () {
      expect(looksAlgorithmicallyGenerated('bcdfghjklmnpqrst.net'), isTrue);
    });

    test('does not flag ordinary short real-world domains', () {
      expect(looksAlgorithmicallyGenerated('google.com'), isFalse);
      expect(looksAlgorithmicallyGenerated('www.wikipedia.org'), isFalse);
      expect(looksAlgorithmicallyGenerated('api.whatsapp.com'), isFalse);
    });

    test('does not flag a bare hostname with no TLD-like second label', () {
      expect(looksAlgorithmicallyGenerated('localhost'), isFalse);
    });
  });

  test('disable() clears the snapshot and stops polling', () async {
    platform.nextConnections = [_conn()];
    await monitor.enable();
    await Future<void>.delayed(Duration.zero);
    expect(monitor.lastSnapshot, isNotEmpty);

    await monitor.disable();
    expect(monitor.isActive, isFalse);
  });
}
