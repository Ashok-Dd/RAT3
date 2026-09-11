import 'dart:async';
import 'package:rat3/core/constants/app_constants.dart';
import 'package:rat3/core/utils/app_utils.dart';
import 'package:rat3/data/models/app_models.dart';
import 'package:rat3/data/services/platform_channel_service.dart';

/// Layer 2 – Network Traffic Analyzer
///
/// Primary source: per-app network usage via `getAppNetworkUsage()` — the native
/// side prefers NetworkStatsManager (accurate, needs "usage access") and falls
/// back to TrafficStats (which can silently read 0 on some devices/kernels; the
/// native layer clamps negative "unsupported" reads to 0 rather than dropping
/// the app, so a quiet device just shows 0 bytes instead of nothing).
/// Secondary source: /proc/net/tcp (Android 9 and below only).
///
/// For the test app detection:
///   When your test app clicks "start network" → it sends data to an IP.
///   TrafficStats will show that app has TX bytes. If the TX bytes increase
///   between two readings, that app is actively sending data RIGHT NOW.
class NetworkMonitor {
  static const String _tag = 'NetworkMonitor';

  final PlatformChannelService _platform;
  NetworkMonitor({required PlatformChannelService platform})
    : _platform = platform;

  final _connectionController = StreamController<NetworkConnection>.broadcast();
  final _alertController = StreamController<AlertEvent>.broadcast();

  Stream<NetworkConnection> get connections => _connectionController.stream;
  Stream<AlertEvent> get alerts => _alertController.stream;

  Timer? _monitorTimer;
  bool _isRunning = false;

  final List<NetworkConnection> _detectedConnections = [];
  List<NetworkConnection> get detectedConnections =>
      List.unmodifiable(_detectedConnections);

  // Previous TX snapshot for delta detection (active upload detection)
  final Map<String, int> _previousTxSnapshot = {};

  // Known malicious IP ranges / suspicious RAT-backdoor ports — shared with
  // ConnectionMonitor via AppConstants (see its doc comment for the honesty
  // caveat: illustrative lists, not a live feed).
  static const List<String> _maliciousIpPrefixes =
      AppConstants.knownMaliciousIpPrefixes;
  static const List<int> _suspiciousPorts = AppConstants.suspiciousPorts;

  // ── Lifecycle ──────────────────────────────────────────────────────────────

  void start() {
    if (_isRunning) return;
    _isRunning = true;
    AppLogger.info(_tag, 'Network monitor started');
    // Poll every 20s — detects active uploads quickly
    _monitorTimer = Timer.periodic(const Duration(seconds: 20), (_) async {
      await _scanNetworkConnections();
    });
  }

  void stop() {
    _monitorTimer?.cancel();
    _monitorTimer = null;
    _isRunning = false;
  }

  Future<List<NetworkConnection>> performScan() async {
    return _scanNetworkConnections();
  }

  // ── Real Network Scan ──────────────────────────────────────────────────────

  Future<List<NetworkConnection>> _scanNetworkConnections() async {
    final results = <NetworkConnection>[];
    try {
      // PRIMARY: Per-app network usage via TrafficStats UID
      // Works on ALL Android versions — never empty
      final appNetUsage = await _platform.getAppNetworkUsage();

      // SECONDARY: TCP connections from /proc/net/tcp (Android 9 and below)
      final tcpConns = await _platform.getNetworkConnections();

      AppLogger.info(
        _tag,
        'Network: ${appNetUsage.length} apps with traffic, '
        '${tcpConns.length} TCP connections',
      );

      // Build a set of active TCP connection remote IPs for cross-referencing
      final activeTcpIps = <String>{};
      for (final c in tcpConns) {
        final remote = c['remoteAddress'] as String? ?? '';
        final ip = _extractIp(remote);
        if (!_isLoopback(ip) && !_isPrivateIp(ip)) {
          activeTcpIps.add(ip);
        }
      }

      // ── Self + system exclusion list ────────────────────────────────────
      // NEVER report on our own app under any circumstances
      const selfPackage = AppConstants.selfPackageName;

      // Skip all well-known system / Google infrastructure packages
      bool shouldSkip(String pkg) {
        if (pkg == selfPackage) return true;
        const skip = [
          'com.android.',
          'android.',
          'com.google.android.gms',
          'com.google.android.gsf',
          'com.google.android.webview',
          'com.google.android.networkstack',
          'com.google.android.permissioncontroller',
          'com.google.android.cellbroadcastreceiver',
          'com.google.android.captiveportallogin',
          'com.google.android.connectivity',
          'com.google.android.gapps',
          'com.google.android.syncadapters',
          'com.google.android.partnersetup',
        ];
        for (final s in skip) {
          if (pkg.startsWith(s) || pkg == s.replaceAll('.', '')) return true;
        }
        return false;
      }

      // Process each app that has network activity
      for (final app in appNetUsage) {
        final pkgName = app['packageName'] as String? ?? '';
        final appName = app['appName'] as String? ?? pkgName;
        final txBytes = (app['txBytes'] as num?)?.toInt() ?? 0;
        final rxBytes = (app['rxBytes'] as num?)?.toInt() ?? 0;

        // Skip self and system packages
        if (shouldSkip(pkgName)) continue;

        // Skip apps with no meaningful traffic (< 1 KB)
        if (txBytes < 1024 && rxBytes < 1024) continue;

        // Detect ACTIVE upload: compare with previous snapshot
        final prevTx = _previousTxSnapshot[pkgName] ?? 0;
        final deltaTx = txBytes - prevTx;
        final isActivelyUploading =
            deltaTx > 50 * 1024; // 50KB+ new since last check
        _previousTxSnapshot[pkgName] = txBytes;

        // Classify based on upload behavior and known signals
        final category = _classifyApp(
          pkgName: pkgName,
          txBytes: txBytes,
          deltaTx: deltaTx,
          isActivelyUploading: isActivelyUploading,
        );

        // Build a meaningful "domain" label since we don't have DNS
        // Use the app name + upload indicator
        final domainLabel = isActivelyUploading
            ? '$appName ⬆ ACTIVE UPLOAD'
            : appName;

        final conn = NetworkConnection(
          id: '${DateTime.now().millisecondsSinceEpoch}_$pkgName',
          domain: domainLabel,
          ipAddress: pkgName, // store package name here for display
          port: 0,
          category: category,
          bytesSent: txBytes,
          bytesReceived: rxBytes,
          detectedAt: DateTime.now(),
          isBackground: isActivelyUploading,
        );

        results.add(conn);
        _processConnection(
          conn,
          appName: appName,
          deltaTx: deltaTx,
          isActivelyUploading: isActivelyUploading,
        );
      }

      // Also process raw TCP connections if available (Android 9-)
      for (int i = 0; i < tcpConns.length; i++) {
        final raw = tcpConns[i];
        final remote = raw['remoteAddress'] as String? ?? '';
        final ip = _extractIp(remote);
        final port = _extractPort(remote);

        if (_isLoopback(ip) || _isPrivateIp(ip)) continue;

        // Only add if not already covered by app usage
        final category = _classifyIp(ip, port);
        if (category == TrafficCategory.malicious ||
            (category == TrafficCategory.suspicious &&
                _isSuspiciousPort(port))) {
          final conn = NetworkConnection(
            id: 'tcp_${DateTime.now().millisecondsSinceEpoch}_$i',
            domain: ip,
            ipAddress: ip,
            port: port,
            category: category,
            bytesSent: 0,
            bytesReceived: 0,
            detectedAt: DateTime.now(),
            isBackground: _isSuspiciousPort(port),
          );
          results.add(conn);
          _processConnection(conn, appName: ip);
        }
      }
    } catch (e) {
      AppLogger.error(_tag, '_scanNetworkConnections error', e);
    }
    return results;
  }

  void _processConnection(
    NetworkConnection conn, {
    required String appName,
    int deltaTx = 0,
    bool isActivelyUploading = false,
  }) {
    _detectedConnections.add(conn);
    if (_detectedConnections.length > 100) _detectedConnections.removeAt(0);
    if (!_connectionController.isClosed) _connectionController.add(conn);
    _emitNetworkAlerts(
      conn,
      appName: appName,
      deltaTx: deltaTx,
      isActivelyUploading: isActivelyUploading,
    );
  }

  // ── App Network Classification ─────────────────────────────────────────────

  TrafficCategory _classifyApp({
    required String pkgName,
    required int txBytes,
    required int deltaTx,
    required bool isActivelyUploading,
  }) {
    // Active large upload is always suspicious — flag it
    if (isActivelyUploading && deltaTx > AppConstants.dataUploadThreshold) {
      return TrafficCategory.malicious;
    }
    if (isActivelyUploading) return TrafficCategory.suspicious;

    // High total TX (> 10MB) from a non-system app → suspicious
    if (txBytes > 10 * 1024 * 1024) return TrafficCategory.suspicious;

    return TrafficCategory.safe;
  }

  TrafficCategory _classifyIp(String ip, int port) {
    for (final prefix in _maliciousIpPrefixes) {
      if (ip.startsWith(prefix)) return TrafficCategory.malicious;
    }
    if (_isSuspiciousPort(port)) return TrafficCategory.suspicious;
    if (_isKnownSafeBlock(ip)) return TrafficCategory.safe;
    return TrafficCategory.suspicious;
  }

  // ── Alert Emission ─────────────────────────────────────────────────────────

  void _emitNetworkAlerts(
    NetworkConnection conn, {
    required String appName,
    int deltaTx = 0,
    bool isActivelyUploading = false,
  }) {
    if (conn.category == TrafficCategory.malicious) {
      _emit(
        id: 'net_malicious_${conn.ipAddress}',
        severity: AlertSeverity.critical,
        title: 'Active Data Exfiltration Detected',
        description:
            '"$appName" is actively sending large amounts of data '
            '(${AppFormatter.formatBytes(deltaTx)} in last 20s)',
        userMessage:
            '"$appName" is uploading ${AppFormatter.formatBytes(deltaTx)} '
            'of data right now. This matches data exfiltration behavior. '
            'The app may be transmitting your personal data without permission.',
      );
    } else if (conn.category == TrafficCategory.suspicious &&
        isActivelyUploading) {
      _emit(
        id: 'net_upload_${conn.ipAddress}_${DateTime.now().minute}',
        severity: AlertSeverity.high,
        title: 'Suspicious Active Upload',
        description: '"$appName" is actively sending data in background',
        userMessage:
            '"$appName" is currently sending data '
            '(${AppFormatter.formatBytes(deltaTx)} uploaded recently). '
            'If you are not actively using this app, this is suspicious.',
      );
    } else if (conn.bytesSent > 10 * 1024 * 1024) {
      _emit(
        id: 'net_highdata_${conn.ipAddress}',
        severity: AlertSeverity.medium,
        title: 'High Data Usage',
        description:
            '"$appName" has sent ${AppFormatter.formatBytes(conn.bytesSent)}',
        userMessage:
            '"$appName" has sent a large amount of data '
            '(${AppFormatter.formatBytes(conn.bytesSent)}). '
            'Review if this matches your expected app activity.',
      );
    }
  }

  void _emit({
    required String id,
    required AlertSeverity severity,
    required String title,
    required String description,
    required String userMessage,
  }) {
    final alert = AlertEvent(
      id: id,
      severity: severity,
      title: title,
      description: description,
      userFriendlyMessage: userMessage,
      timestamp: DateTime.now(),
      source: 'Network Monitor',
    );
    if (!_alertController.isClosed) _alertController.add(alert);
  }

  // ── Helpers ────────────────────────────────────────────────────────────────

  bool _isSuspiciousPort(int port) => _suspiciousPorts.contains(port);
  bool _isLoopback(String ip) =>
      ip.startsWith('127.') || ip == '::1' || ip == '0.0.0.0';
  bool _isPrivateIp(String ip) =>
      ip.startsWith('10.') ||
      ip.startsWith('192.168.') ||
      ip.startsWith('172.16.') ||
      ip.startsWith('172.17.') ||
      ip.startsWith('172.18.') ||
      ip.startsWith('172.19.') ||
      ip.startsWith('172.2') ||
      ip.startsWith('172.3');
  bool _isKnownSafeBlock(String ip) =>
      ip.startsWith('142.250.') ||
      ip.startsWith('172.217.') ||
      ip.startsWith('216.58.') ||
      ip.startsWith('8.8.') ||
      ip.startsWith('104.16.') ||
      ip.startsWith('1.1.1.') ||
      ip.startsWith('54.') ||
      ip.startsWith('52.');

  String _extractIp(String addrPort) {
    final last = addrPort.lastIndexOf(':');
    return last > 0 ? addrPort.substring(0, last) : addrPort;
  }

  int _extractPort(String addrPort) {
    final last = addrPort.lastIndexOf(':');
    if (last < 0) return 0;
    return int.tryParse(addrPort.substring(last + 1)) ?? 0;
  }

  void dispose() {
    stop();
    _connectionController.close();
    _alertController.close();
  }
}
