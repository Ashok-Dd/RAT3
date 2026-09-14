import 'dart:async';
import 'package:rat3/core/constants/app_constants.dart';
import 'package:rat3/core/utils/app_utils.dart';
import 'package:rat3/data/models/app_models.dart';
import 'package:rat3/data/services/platform_channel_service.dart';

/// Layer 1 – Runtime Behavior Monitor
///
/// ALL data is REAL — sourced from Android native APIs via PlatformChannelService:
///
///   CPU Usage      → /proc/stat (read twice, delta computed in Kotlin)
///   Memory         → ActivityManager.MemoryInfo
///   Processes      → ActivityManager.getRunningAppProcesses()
///   App Usage      → UsageStatsManager (past 24 hours)
///   Security Flags → Developer options, USB debugging, root detection
///
/// No Random(), no simulated values.
class RuntimeMonitor {
  static const String _tag = 'RuntimeMonitor';

  final PlatformChannelService _platform;

  RuntimeMonitor({required PlatformChannelService platform})
    : _platform = platform;

  final _eventController = StreamController<RuntimeEvent>.broadcast();
  final _alertController = StreamController<AlertEvent>.broadcast();

  Stream<RuntimeEvent> get runtimeEvents => _eventController.stream;
  Stream<AlertEvent> get alerts => _alertController.stream;

  Timer? _monitorTimer;
  bool _isRunning = false;
  int _consecutiveCpuSpikes = 0;

  final List<RuntimeEvent> _eventHistory = [];
  List<RuntimeEvent> get eventHistory => List.unmodifiable(_eventHistory);

  // ── Lifecycle ──────────────────────────────────────────────────────────────

  void start() {
    if (_isRunning) return;
    _isRunning = true;
    AppLogger.info(_tag, 'Runtime monitor started (REAL data mode)');

    // Poll every 15 seconds — real /proc/stat reads take ~250ms each
    _monitorTimer = Timer.periodic(const Duration(seconds: 15), (_) async {
      await _checkCpuUsage();
      await _checkMemory();
      await _checkSecurityFlags();
    });
  }

  void stop() {
    _monitorTimer?.cancel();
    _monitorTimer = null;
    _isRunning = false;
    AppLogger.info(_tag, 'Runtime monitor stopped');
  }

  /// Full one-shot scan — called by AppController on manual/auto scan.
  Future<List<RuntimeEvent>> performScan() async {
    final events = <RuntimeEvent>[];

    // 1. Real CPU reading
    final cpuEvent = await _checkCpuUsage();
    if (cpuEvent != null) events.add(cpuEvent);

    // 2. Real memory check
    final memEvent = await _checkMemory();
    if (memEvent != null) events.add(memEvent);

    // 3. Real running processes — detect high-importance background processes
    final procEvents = await _checkRunningProcesses();
    events.addAll(procEvents);

    // 4. Real security flags — root, USB debug, developer options
    final flagEvents = await _checkSecurityFlags();
    events.addAll(flagEvents);

    // 5. Real app usage — detect apps with excessive background time
    final usageEvents = await _checkAppUsageStats();
    events.addAll(usageEvents);

    return events;
  }

  // ── Real Check: CPU ────────────────────────────────────────────────────────

  Future<RuntimeEvent?> _checkCpuUsage() async {
    try {
      // Kotlin reads /proc/stat twice with 250ms gap and returns real CPU%
      final cpuUsage = await _platform.getCpuUsage();

      if (cpuUsage < 0) {
        // -1 means /proc/stat was inaccessible — not an error worth alerting
        AppLogger.warning(_tag, 'CPU reading unavailable on this device');
        return null;
      }

      AppLogger.info(_tag, 'Real CPU usage: ${cpuUsage.toStringAsFixed(1)}%');

      if (cpuUsage > AppConstants.cpuSpikeThreshold) {
        _consecutiveCpuSpikes++;
        final event = _addEvent(
          type: RuntimeEventType.cpuSpike,
          value: cpuUsage,
          details: 'Real CPU usage: ${cpuUsage.toStringAsFixed(1)}%',
        );

        // Only alert after 2 consecutive spikes to avoid false positives
        if (_consecutiveCpuSpikes >= 2) {
          _emitAlert(
            event: event,
            severity: cpuUsage > 90
                ? AlertSeverity.critical
                : AlertSeverity.high,
            title: 'High CPU Usage Detected',
            userMessage:
                'Your device CPU is at ${cpuUsage.toStringAsFixed(0)}%. '
                'A background process may be consuming excessive resources, '
                'which can indicate malicious activity.',
          );
        }
        return event;
      } else {
        _consecutiveCpuSpikes = 0; // Reset on normal reading
      }
    } catch (e) {
      AppLogger.error(_tag, '_checkCpuUsage error', e);
    }
    return null;
  }

  // ── Real Check: Memory ─────────────────────────────────────────────────────

  Future<RuntimeEvent?> _checkMemory() async {
    try {
      final info = await _platform.getMemoryInfo();
      if (info.isEmpty) return null;

      final totalRam = (info['totalRam'] as num?)?.toInt() ?? 0;
      final availableRam = (info['availableRam'] as num?)?.toInt() ?? 0;
      final isLowMemory = (info['lowMemory'] as bool?) ?? false;

      if (totalRam == 0) return null;

      final usedPct = ((totalRam - availableRam) / totalRam * 100);
      AppLogger.info(
        _tag,
        'Memory: ${AppFormatter.formatBytes(totalRam - availableRam)} used '
        '/ ${AppFormatter.formatBytes(totalRam)} total '
        '(${usedPct.toStringAsFixed(1)}%)',
      );

      if (isLowMemory || usedPct > 90) {
        final event = _addEvent(
          type: RuntimeEventType.memoryAnomaly,
          value: usedPct,
          details:
              'Memory at ${usedPct.toStringAsFixed(1)}% '
              '(${AppFormatter.formatBytes(availableRam)} free)',
        );
        _emitAlert(
          event: event,
          severity: AlertSeverity.medium,
          title: 'Critical Memory Usage',
          userMessage:
              'Device memory is critically low (${usedPct.toStringAsFixed(0)}% used). '
              'This can be caused by a memory-leaking malicious app.',
        );
        return event;
      }
    } catch (e) {
      AppLogger.error(_tag, '_checkMemory error', e);
    }
    return null;
  }

  // ── Real Check: Running Processes ──────────────────────────────────────────

  // Honesty note: since Android 5.1 (API 21+), ActivityManager.getRunningAppProcesses()
  // is restricted to the calling app's own process for a normal, non-system app — this
  // is a platform limitation, not something a permission can unlock. In practice this
  // list is just RAT3's own process(es), so backgroundProcs.length can never realistically
  // exceed the threshold below; the rule is effectively inert on a real device rather than
  // misleading (it will never falsely fire from other apps' activity, only never fire at
  // all). Left in place rather than removed, in case a future Android version or device
  // policy widens what's visible here.
  Future<List<RuntimeEvent>> _checkRunningProcesses() async {
    final events = <RuntimeEvent>[];
    try {
      final processes = await _platform.getRunningProcesses();
      AppLogger.info(_tag, 'Running processes: ${processes.length}');

      // importance 400 = IMPORTANCE_BACKGROUND, 500 = IMPORTANCE_SERVICE
      // Any process with importance > 300 still running is potentially suspicious
      // if it has been doing so excessively — we check count here
      final backgroundProcs = processes.where((p) {
        final importance = (p['importance'] as num?)?.toInt() ?? 0;
        return importance >= 400; // Background and beyond
      }).toList();

      if (backgroundProcs.length > 10) {
        final event = _addEvent(
          type: RuntimeEventType.backgroundExecution,
          value: backgroundProcs.length.toDouble(),
          details: '${backgroundProcs.length} processes running in background',
        );
        _emitAlert(
          event: event,
          severity: AlertSeverity.medium,
          title: 'Excessive Background Processes',
          userMessage:
              '${backgroundProcs.length} apps are currently running silently '
              'in the background. This is abnormally high and may indicate '
              'unwanted background activity.',
        );
        events.add(event);
      }
    } catch (e) {
      AppLogger.error(_tag, '_checkRunningProcesses error', e);
    }
    return events;
  }

  // ── Real Check: Security Flags ─────────────────────────────────────────────

  Future<List<RuntimeEvent>> _checkSecurityFlags() async {
    final events = <RuntimeEvent>[];
    try {
      // Single call returns all flags — avoids multiple round-trips
      final flags = await _platform.getSecurityFlags();
      if (flags.isEmpty) return events;

      final isRooted = flags['isRooted'] as bool? ?? false;
      final usbDebugging = flags['isUsbDebuggingEnabled'] as bool? ?? false;
      final developerOptions =
          flags['isDeveloperOptionsEnabled'] as bool? ?? false;

      AppLogger.info(
        _tag,
        'Security flags — rooted:$isRooted usbDebug:$usbDebugging devOptions:$developerOptions',
      );

      if (isRooted) {
        final event = _addEvent(
          type: RuntimeEventType.serviceRestart,
          value: 1,
          details: 'Device root access detected via multi-signal heuristic',
        );
        _emitAlert(
          event: event,
          severity: AlertSeverity.critical,
          title: 'Device is Rooted',
          userMessage:
              'Root access was detected on this device. Rooted devices have '
              'significantly reduced security and are vulnerable to RAT '
              'installation and data theft.',
          // Stable id (not event.id, which is a fresh timestamp every poll) so
          // AlertEngine's Tier-1 dedup actually catches repeats of the same
          // condition. notify:false — the native ScanForegroundService already
          // pushes an OS notification for this; we still want it in-app fast.
          id: 'runtime_rooted',
          notify: false,
        );
        events.add(event);
      }

      // USB debugging / developer options are deliberately NOT alerted on their own here
      // -- they're ordinary, common settings for developers and power users, and a RAT's
      // threat model is remote/network control, not local USB access. This mirrors the
      // fix already made to the Dashboard's RuleBasedScorer (see its "rules that were
      // deliberately removed or changed" doc section); this layer previously kept firing
      // both standalone alerts independently, since it's a separate implementation that
      // hadn't been updated to match. Only root + USB debugging together is worth naming.
      if (isRooted && usbDebugging) {
        final event = _addEvent(
          type: RuntimeEventType.serviceRestart,
          value: 2,
          details: 'Rooted device with USB debugging enabled',
        );
        _emitAlert(
          event: event,
          severity: AlertSeverity.medium,
          title: 'Rooted Device With USB Debugging Enabled',
          userMessage:
              'Together these meaningfully widen what anyone with physical access to '
              'this device could do — on their own, neither is unusual for a developer.',
          id: 'runtime_root_usb_debug',
          notify: false, // native scan already notifies for this condition
        );
        events.add(event);
      }
    } catch (e) {
      AppLogger.error(_tag, '_checkSecurityFlags error', e);
    }
    return events;
  }

  // ── Real Check: App Usage Stats ────────────────────────────────────────────

  Future<List<RuntimeEvent>> _checkAppUsageStats() async {
    final events = <RuntimeEvent>[];
    try {
      final stats = await _platform.getUsageStats();
      if (stats.isEmpty) {
        return events; // Permission not granted — skip silently
      }

      // Flag any app with more than 2 hours of foreground time in past 24h
      // that is not a system launcher/home screen app
      const twoHoursMs = 2 * 60 * 60 * 1000;

      final heavyApps = stats.where((s) {
        final time = (s['totalTimeInForeground'] as num?)?.toInt() ?? 0;
        final pkg = s['packageName'] as String? ?? '';
        // Filter out known launchers / system apps
        final isKnownSystem =
            pkg.contains('launcher') ||
            pkg.contains('systemui') ||
            pkg == 'android';
        return time > twoHoursMs && !isKnownSystem;
      }).toList();

      AppLogger.info(
        _tag,
        'Usage stats: ${stats.length} apps, ${heavyApps.length} heavy users',
      );

      for (final app in heavyApps.take(3)) {
        final pkg = app['packageName'] as String? ?? 'Unknown';
        final time = (app['totalTimeInForeground'] as num?)?.toInt() ?? 0;
        final hrs = (time / 3600000).toStringAsFixed(1);

        final event = _addEvent(
          type: RuntimeEventType.backgroundExecution,
          value: time / 60000, // Store as minutes
          details: '$pkg used for ${hrs}h in foreground today',
        );
        _emitAlert(
          event: event,
          severity: AlertSeverity.low,
          title: 'High App Usage Detected',
          userMessage:
              'The app "$pkg" has been active for $hrs hours today. '
              'If you did not use this app, it may be running without your knowledge.',
        );
        events.add(event);
      }
    } catch (e) {
      AppLogger.error(_tag, '_checkAppUsageStats error', e);
    }
    return events;
  }

  // ── Helpers ────────────────────────────────────────────────────────────────

  RuntimeEvent _addEvent({
    required RuntimeEventType type,
    required double value,
    required String details,
  }) {
    final event = RuntimeEvent(
      id: DateTime.now().millisecondsSinceEpoch.toString(),
      type: type,
      value: value,
      details: details,
      timestamp: DateTime.now(),
    );
    _eventHistory.add(event);
    if (_eventHistory.length > 200) _eventHistory.removeAt(0);
    return event;
  }

  /// @param id Stable, condition-specific alert id. Defaults to a fresh
  ///   timestamp-based id (fine for transient events like a CPU spike) — pass
  ///   an explicit stable id for persistent device-state conditions so
  ///   AlertEngine's Tier-1 "seen this id already" dedup actually applies.
  /// @param notify Whether this should push an OS notification. Defaults to
  ///   true; set false when another layer (the native background scan) is
  ///   already the notifier of record for this exact condition, to avoid
  ///   duplicate pushes for the same finding.
  void _emitAlert({
    required RuntimeEvent event,
    required AlertSeverity severity,
    required String title,
    required String userMessage,
    String? id,
    bool notify = true,
  }) {
    final alert = AlertEvent(
      id: id ?? 'runtime_${event.id}',
      severity: severity,
      title: title,
      description: event.details,
      userFriendlyMessage: userMessage,
      timestamp: event.timestamp,
      source: 'Runtime Monitor',
      notify: notify,
    );
    if (!_alertController.isClosed) _alertController.add(alert);
  }

  void dispose() {
    stop();
    _eventController.close();
    _alertController.close();
  }
}
