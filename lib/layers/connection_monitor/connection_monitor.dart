import 'dart:async';
import 'dart:math';

import 'package:rat3/core/constants/app_constants.dart';
import 'package:rat3/core/utils/app_utils.dart';
import 'package:rat3/data/models/app_models.dart';
import 'package:rat3/data/services/platform_channel_service.dart';

/// ConnectionMonitor — the real, process-level network connection view.
///
/// Replaces the "how many MB did this app use" framing with the actual
/// question: is any process continuously or repeatedly communicating with a
/// remote endpoint in a way that could indicate RAT-like behavior? Backed by
/// `RatVpnService` (Kotlin) — a local, user-opted-in VPN that is the only
/// non-root way to see real per-connection remote IP/port/protocol on
/// Android 10+ (see PlatformChannelService.getActiveConnections doc comment).
///
/// Correlation, mirroring the App Trust Engine's philosophy — a single
/// ordinary connection is never flagged:
///   NORMAL        — everything else. A trusted app's routine HTTPS traffic.
///   INVESTIGATE   — persistent/repeated communication to the same endpoint
///                   (re-observed across multiple polls), OR the owning app
///                   is itself untrusted (see [untrustedPackages]).
///   SUSPICIOUS    — persistent/repeated communication AND (an untrusted
///                   owning app OR a known-bad port/IP match) — i.e. two
///                   correlated signals, not one.
class ConnectionMonitor {
  static const String _tag = 'ConnectionMonitor';

  final PlatformChannelService _platform;
  ConnectionMonitor({required PlatformChannelService platform})
    : _platform = platform;

  final _connectionsController =
      StreamController<List<ConnectionEvidence>>.broadcast();
  final _alertController = StreamController<AlertEvent>.broadcast();

  Stream<List<ConnectionEvidence>> get connections =>
      _connectionsController.stream;
  Stream<AlertEvent> get alerts => _alertController.stream;

  Timer? _pollTimer;
  bool _isActive = false;
  bool get isActive => _isActive;

  List<ConnectionEvidence> _lastSnapshot = [];
  List<ConnectionEvidence> get lastSnapshot =>
      List.unmodifiable(_lastSnapshot);

  /// Package names the App Trust Engine has already flagged NEEDS_REVIEW or
  /// above in the most recent Scan All Apps run. Set externally (by
  /// AppController) after each scan — a connection from one of these apps
  /// needs less additional evidence to read as concerning, matching the
  /// spec's "unknown app + persistent connection -> higher confidence"
  /// correlation example.
  Set<String> untrustedPackages = {};

  final Set<String> _alertedKeys = {};

  // ── Lifecycle ──────────────────────────────────────────────────────────────

  /// Triggers the system VPN consent dialog if needed. Returns false if the
  /// user declined or the service failed to start — never throws.
  Future<bool> enable() async {
    final started = await _platform.startVpnMonitor();
    if (started) {
      _isActive = true;
      _pollTimer?.cancel();
      _pollTimer = Timer.periodic(const Duration(seconds: 6), (_) => _poll());
      unawaited(_poll());
    }
    return started;
  }

  Future<void> disable() async {
    _pollTimer?.cancel();
    _pollTimer = null;
    _isActive = false;
    _lastSnapshot = [];
    _alertedKeys.clear();
    if (!_connectionsController.isClosed) _connectionsController.add([]);
    await _platform.stopVpnMonitor();
  }

  /// Call once at startup to reflect a monitor that was already running
  /// (e.g. the process restarted while the foreground service kept going).
  Future<void> syncActiveState() async {
    final active = await _platform.isVpnMonitorActive();
    if (active && !_isActive) {
      _isActive = true;
      _pollTimer?.cancel();
      _pollTimer = Timer.periodic(const Duration(seconds: 6), (_) => _poll());
      unawaited(_poll());
    }
  }

  Future<void> _poll() async {
    try {
      final raw = await _platform.getActiveConnections();
      final evaluated = raw
          .map(ConnectionEvidence.fromMap)
          .map(_assess)
          .toList();
      _lastSnapshot = evaluated;
      if (!_connectionsController.isClosed) {
        _connectionsController.add(evaluated);
      }
      for (final c in evaluated) {
        if (c.assessment != ConnectionAssessment.suspicious) continue;
        _emitAlert(c);
      }
    } catch (e) {
      AppLogger.error(_tag, 'poll failed', e);
    }
  }

  // ── Correlation ────────────────────────────────────────────────────────────

  ConnectionEvidence _assess(ConnectionEvidence c) {
    final reasons = <String>[];
    final portMatch = AppConstants.suspiciousPorts.contains(c.remotePort);
    final ipMatch = AppConstants.knownMaliciousIpPrefixes.any(
      c.remoteAddress.startsWith,
    );
    final untrustedOwner = untrustedPackages.contains(c.packageName);
    final domain = c.queriedDomain;
    final looksAlgorithmic =
        domain != null && looksAlgorithmicallyGenerated(domain);

    if (c.isPersistent) {
      reasons.add(
        'Repeated/persistent communication with ${c.remoteAddress}:${c.remotePort} '
        '(${c.reconnectCount + 1} connections observed)',
      );
    }
    if (portMatch) {
      reasons.add('Port ${c.remotePort} matches a known RAT/backdoor port');
    }
    if (ipMatch) {
      reasons.add('Remote address matches a known-malicious IP range');
    }
    if (untrustedOwner) {
      reasons.add('"${c.appName}" has other unresolved security findings');
    }
    if (looksAlgorithmic) {
      reasons.add(
        'Queried domain "$domain" has unusual, algorithmically-generated-looking '
        'characteristics (a DNS-based C2 pattern) — though random-looking '
        'subdomains also occur on legitimate CDN/cloud infrastructure',
      );
    }

    // Two or more correlated signals -> SUSPICIOUS. Exactly one -> just worth
    // a look. Zero -> normal, no matter how much data moved.
    final strongSignals = [
      c.isPersistent,
      portMatch,
      ipMatch,
      untrustedOwner,
      looksAlgorithmic,
    ].where((b) => b).length;

    final assessment = switch (strongSignals) {
      0 => ConnectionAssessment.normal,
      1 => ConnectionAssessment.investigate,
      _ => ConnectionAssessment.suspicious,
    };

    return c.copyWith(assessment: assessment, reasons: reasons);
  }

  void _emitAlert(ConnectionEvidence c) {
    final key = '${c.protocol}_${c.packageName}_${c.remoteAddress}_${c.remotePort}';
    if (_alertedKeys.contains(key)) return;
    _alertedKeys.add(key);

    final alert = AlertEvent(
      id: 'conn_$key',
      severity: AlertSeverity.high,
      title: 'Suspicious network connection — "${c.appName}"',
      description: c.reasons.join('. '),
      userFriendlyMessage:
          '"${c.appName}" is communicating with ${c.remoteAddress}:${c.remotePort} '
          '(${c.protocol}). ${c.reasons.join(". ")}.',
      timestamp: DateTime.now(),
      source: 'Connection Monitor',
    );
    if (!_alertController.isClosed) _alertController.add(alert);
  }

  void dispose() {
    _pollTimer?.cancel();
    _connectionsController.close();
    _alertController.close();
  }
}

/// A lightweight, conservative heuristic for domain-generation-algorithm-style
/// hostnames (e.g. "xqzptmvwklrf.com") — one weak signal among several in
/// [ConnectionMonitor._assess], exactly like a suspicious port or IP match. It
/// never escalates a connection to SUSPICIOUS by itself, which matters here
/// specifically: random-looking subdomains are also routine on legitimate
/// CDN/cloud infrastructure (S3 buckets, Azure blob storage, Akamai edge
/// nodes all do this), a well-known false-positive source for DGA heuristics
/// in general — so this requires BOTH unusual length AND unusual character
/// entropy (or a long consonant run) before it counts as a signal at all.
bool looksAlgorithmicallyGenerated(String domain) {
  final labels = domain.toLowerCase().split('.');
  if (labels.length < 2) return false;
  // The label right before the TLD is what DGA malware actually randomizes
  // ("xqzptmvwklrf" in "xqzptmvwklrf.com"), not the full hostname.
  final label = labels[labels.length - 2];
  if (label.length < 12) return false;

  final counts = <String, int>{};
  for (final ch in label.split('')) {
    counts[ch] = (counts[ch] ?? 0) + 1;
  }
  var entropy = 0.0;
  for (final count in counts.values) {
    final p = count / label.length;
    entropy -= p * (log(p) / ln2);
  }

  const vowels = {'a', 'e', 'i', 'o', 'u'};
  final letters = RegExp(r'^[a-z]$');
  var longestConsonantRun = 0;
  var run = 0;
  for (final ch in label.split('')) {
    if (letters.hasMatch(ch) && !vowels.contains(ch)) {
      run++;
      if (run > longestConsonantRun) longestConsonantRun = run;
    } else {
      run = 0;
    }
  }

  return entropy > 3.3 || longestConsonantRun >= 6;
}
