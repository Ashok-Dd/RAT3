import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:rat3/core/constants/app_constants.dart';
import 'package:rat3/core/theme/app_theme.dart';
import 'package:rat3/core/utils/app_utils.dart';
import 'package:rat3/data/models/app_models.dart';
import 'package:rat3/data/services/app_controller.dart';
import 'package:rat3/data/services/platform_channel_service.dart';
import 'package:rat3/presentation/onboarding/onboarding_screen.dart';

/// NetworkScreen — process-level network connection monitor.
///
/// RAT3's Network tab is NOT a data-usage tracker: a single ordinary HTTPS
/// connection from a trusted app is never a finding, no matter how much data
/// it moves. The question this tab answers is "is any process continuously
/// or repeatedly communicating with a remote endpoint in a way that could
/// indicate RAT-like behavior?" — real per-connection process/remote-IP/
/// port/protocol/persistence, via `ConnectionMonitor` (backed by a local,
/// user-opted-in VPN — see RatVpnService.kt's doc comment for why a VPN is
/// the only non-root way to get this on Android 10+).
///
/// The real-time monitor is OFF by default (it requires the system VPN
/// consent dialog). While off, this screen falls back to an aggregate
/// per-app byte-usage list — useful supplementary info, but explicitly
/// secondary, not the headline, and never itself a verdict.
class NetworkScreen extends StatefulWidget {
  const NetworkScreen({super.key});

  @override
  State<NetworkScreen> createState() => _NetworkScreenState();
}

class _NetworkScreenState extends State<NetworkScreen> {
  final _platform = PlatformChannelService();

  bool _loading = false;
  String? _error;
  List<_AppTraffic> _apps = [];
  DateTime? _lastLoaded;
  bool _usageAccessGranted = true;
  bool _togglingMonitor = false;

  _ConnFilter _filter = _ConnFilter.all;

  // System packages to skip — we only care about user apps
  static const _skipPfx = [
    'com.android.',
    'android',
    'com.google.android.gms',
    'com.google.android.gsf',
    'com.google.android.webview',
    'com.google.android.networkstack',
    'com.google.android.permissioncontroller',
    'com.google.android.cellbroadcast',
    'com.google.android.captiveportal',
    'com.google.android.connectivity',
    'com.google.android.ext.',
    'com.android.vending',
    AppConstants.selfPackageName,
  ];

  bool _skip(String pkg) =>
      _skipPfx.any((s) => pkg.startsWith(s) || pkg == s.replaceAll('.', ''));

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final flags = await _platform.getSecurityFlags();
      final raw = await _platform.getAppNetworkUsage();

      final apps = <_AppTraffic>[];
      for (final r in raw) {
        final pkg = r['packageName'] as String? ?? '';
        final name = r['appName'] as String? ?? pkg;
        final tx = (r['txBytes'] as num?)?.toInt() ?? 0;
        final rx = (r['rxBytes'] as num?)?.toInt() ?? 0;
        if (_skip(pkg)) continue;
        apps.add(_AppTraffic(pkg: pkg, name: name, txBytes: tx, rxBytes: rx));
      }
      apps.sort((a, b) => b.txBytes.compareTo(a.txBytes));

      setState(() {
        _apps = apps;
        _lastLoaded = DateTime.now();
        _loading = false;
        _usageAccessGranted = flags['hasUsageStatsPermission'] == true;
      });
    } catch (e) {
      setState(() {
        _error = e.toString();
        _loading = false;
      });
    }
  }

  Future<void> _toggleMonitor(AppController ctrl, bool enable) async {
    setState(() => _togglingMonitor = true);
    try {
      if (enable) {
        final started = await ctrl.enableConnectionMonitor();
        if (!started && mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text(
                'Real-time monitoring needs the system VPN permission — it was not granted.',
              ),
            ),
          );
        }
      } else {
        await ctrl.disableConnectionMonitor();
      }
    } finally {
      if (mounted) setState(() => _togglingMonitor = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final ctrl = context.watch<AppController>();
    final vpnActive = ctrl.isConnectionMonitorActive;
    final evidence = ctrl.connectionEvidence;

    return Scaffold(
      backgroundColor: AppTheme.backgroundPrimary,
      body: ListView(
        padding: const EdgeInsets.fromLTRB(16, 16, 16, 100),
        children: [
          Text(
            'NETWORK MONITOR',
            style: AppTheme.labelSmall.copyWith(
              color: AppTheme.neonCyan,
              letterSpacing: 2,
              fontSize: 11,
              fontWeight: FontWeight.w800,
            ),
          ),
          const SizedBox(height: 4),
          Text(
            'Real per-connection activity, not data usage — a single ordinary '
            'connection from a trusted app is never flagged.',
            style: AppTheme.bodyMedium.copyWith(
              color: AppTheme.textMuted,
              fontSize: 11,
            ),
          ),
          const SizedBox(height: 14),

          _MonitorToggleCard(
            active: vpnActive,
            busy: _togglingMonitor,
            onChanged: (v) => _toggleMonitor(ctrl, v),
          ),

          if (vpnActive) ...[
            const SizedBox(height: 16),
            _buildConnectionSection(evidence),
          ],

          const SizedBox(height: 20),
          _buildUsageSection(vpnActive),
        ],
      ),
    );
  }

  // ── Real-time connection section ────────────────────────────────────────

  Widget _buildConnectionSection(List<ConnectionEvidence> evidence) {
    final active = evidence.where((c) => c.isActive).length;
    final suspicious = evidence
        .where((c) => c.assessment == ConnectionAssessment.suspicious)
        .length;
    final persistent = evidence.where((c) => c.isPersistent).length;

    final filtered = switch (_filter) {
      _ConnFilter.all => evidence,
      _ConnFilter.active => evidence.where((c) => c.isActive).toList(),
      _ConnFilter.suspicious => evidence
          .where((c) => c.assessment != ConnectionAssessment.normal)
          .toList(),
    };

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            _summaryChip('$active', 'ACTIVE', AppTheme.neonGreen),
            const SizedBox(width: 8),
            _summaryChip(
              '$suspicious',
              'SUSPICIOUS',
              suspicious > 0 ? AppTheme.alertOrange : AppTheme.textMuted,
            ),
            const SizedBox(width: 8),
            _summaryChip('$persistent', 'PERSISTENT', AppTheme.neonCyan),
          ],
        ),
        const SizedBox(height: 10),
        Row(
          children: [
            _FilterBtn(
              label: 'ALL',
              count: evidence.length,
              active: _filter == _ConnFilter.all,
              onTap: () => setState(() => _filter = _ConnFilter.all),
            ),
            const SizedBox(width: 8),
            _FilterBtn(
              label: 'ACTIVE NOW',
              count: active,
              active: _filter == _ConnFilter.active,
              onTap: () => setState(() => _filter = _ConnFilter.active),
            ),
            const SizedBox(width: 8),
            _FilterBtn(
              label: 'NEEDS REVIEW',
              count: evidence
                  .where((c) => c.assessment != ConnectionAssessment.normal)
                  .length,
              active: _filter == _ConnFilter.suspicious,
              color: AppTheme.alertOrange,
              onTap: () => setState(() => _filter = _ConnFilter.suspicious),
            ),
          ],
        ),
        const SizedBox(height: 10),
        if (filtered.isEmpty)
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 24),
            child: Center(
              child: Text(
                evidence.isEmpty
                    ? 'Watching for connections…'
                    : 'No connections match this filter',
                style: AppTheme.bodyMedium.copyWith(color: AppTheme.textMuted),
              ),
            ),
          )
        else ...[
          // Kotlin already sorts by most-recently-seen first, so capping here keeps the most
          // relevant entries. Rendering everything unbounded (a session can accumulate hundreds
          // of short-lived flows within minutes of ordinary browsing) visibly janks the list.
          ...filtered
              .take(_maxRenderedConnections)
              .map(
                (c) => _ConnectionCard(
                  connection: c,
                  onTap: () => _showConnectionDetail(c),
                ),
              ),
          if (filtered.length > _maxRenderedConnections)
            Padding(
              padding: const EdgeInsets.symmetric(vertical: 10),
              child: Center(
                child: Text(
                  '+ ${filtered.length - _maxRenderedConnections} more (showing most recent $_maxRenderedConnections)',
                  style: AppTheme.labelSmall.copyWith(
                    color: AppTheme.textMuted,
                  ),
                ),
              ),
            ),
        ],
      ],
    );
  }

  static const _maxRenderedConnections = 40;

  void _showConnectionDetail(ConnectionEvidence c) {
    showModalBottomSheet(
      context: context,
      backgroundColor: AppTheme.backgroundCard,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(16)),
      ),
      builder: (_) => _ConnectionDetailSheet(connection: c),
    );
  }

  Widget _summaryChip(String count, String label, Color color) => Expanded(
    child: Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 8),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(6),
        border: Border.all(color: color.withValues(alpha: 0.35)),
      ),
      child: Column(
        children: [
          Text(
            count,
            style: AppTheme.bodyLarge.copyWith(
              color: color,
              fontWeight: FontWeight.w800,
            ),
          ),
          Text(
            label,
            style: AppTheme.labelSmall.copyWith(color: color, fontSize: 8),
          ),
        ],
      ),
    ),
  );

  // ── Aggregate byte-usage section (secondary, supplementary info) ────────

  Widget _buildUsageSection(bool vpnActive) {
    final totalTx = _apps.fold<int>(0, (s, a) => s + a.txBytes);
    final totalRx = _apps.fold<int>(0, (s, a) => s + a.rxBytes);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Text(
              vpnActive ? 'DATA USAGE (SUPPLEMENTARY)' : 'DATA USAGE',
              style: AppTheme.labelSmall.copyWith(
                color: AppTheme.textMuted,
                letterSpacing: 1.5,
                fontSize: 10,
              ),
            ),
            const Spacer(),
            if (_loading)
              const SizedBox(
                width: 14,
                height: 14,
                child: CircularProgressIndicator(
                  strokeWidth: 2,
                  color: AppTheme.textMuted,
                ),
              )
            else
              GestureDetector(
                onTap: _load,
                child: Icon(
                  Icons.refresh_rounded,
                  size: 16,
                  color: AppTheme.textMuted,
                ),
              ),
          ],
        ),
        if (!vpnActive) ...[
          const SizedBox(height: 4),
          Text(
            'Aggregate bytes sent/received per app — no per-connection detail '
            '(remote IP/port) without real-time monitoring enabled above.',
            style: AppTheme.bodyMedium.copyWith(
              color: AppTheme.textMuted,
              fontSize: 10,
            ),
          ),
        ],
        const SizedBox(height: 10),

        if (!_loading && _error == null && !_usageAccessGranted)
          Padding(
            padding: const EdgeInsets.only(bottom: 10),
            child: GestureDetector(
              onTap: () => Navigator.of(context).push(
                MaterialPageRoute<void>(
                  builder: (_) => const OnboardingScreen(),
                ),
              ),
              child: Container(
                padding: const EdgeInsets.symmetric(
                  horizontal: 12,
                  vertical: 10,
                ),
                decoration: BoxDecoration(
                  color: AppTheme.neonOrange.withValues(alpha: 0.08),
                  borderRadius: BorderRadius.circular(6),
                  border: Border.all(
                    color: AppTheme.neonOrange.withValues(alpha: 0.35),
                  ),
                ),
                child: Row(
                  children: [
                    const Icon(
                      Icons.info_outline,
                      size: 16,
                      color: AppTheme.neonOrange,
                    ),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        'Usage access is off, so per-app totals may read 0. Tap to grant it.',
                        style: AppTheme.bodyMedium.copyWith(
                          color: AppTheme.neonOrange,
                          fontSize: 11,
                        ),
                      ),
                    ),
                    const Icon(
                      Icons.chevron_right,
                      size: 16,
                      color: AppTheme.neonOrange,
                    ),
                  ],
                ),
              ),
            ),
          ),

        if (_error != null)
          Text(_error!, style: const TextStyle(color: AppTheme.alertRed))
        else if (_apps.isEmpty && !_loading)
          Text(
            'No network usage data found yet.',
            style: AppTheme.bodyMedium.copyWith(color: AppTheme.textMuted),
          )
        else ...[
          Row(
            children: [
              Expanded(
                child: Text(
                  'Sent ${AppFormatter.formatBytes(totalTx)}  ·  '
                  'Received ${AppFormatter.formatBytes(totalRx)}',
                  style: AppTheme.bodyMedium.copyWith(
                    color: AppTheme.textSecondary,
                    fontSize: 11,
                  ),
                ),
              ),
              if (_lastLoaded != null)
                Text(
                  _fmt(_lastLoaded!),
                  style: AppTheme.labelSmall.copyWith(
                    color: AppTheme.textMuted,
                    fontSize: 9,
                  ),
                ),
            ],
          ),
          const SizedBox(height: 8),
          ..._apps.take(vpnActive ? 5 : _apps.length).map(_buildUsageRow),
        ],
      ],
    );
  }

  Widget _buildUsageRow(_AppTraffic app) => Padding(
    padding: const EdgeInsets.symmetric(vertical: 5),
    child: Row(
      children: [
        Expanded(
          child: Text(
            app.name,
            style: AppTheme.bodyMedium.copyWith(fontSize: 11),
            overflow: TextOverflow.ellipsis,
          ),
        ),
        Text(
          '↑${AppFormatter.formatBytes(app.txBytes)}',
          style: AppTheme.labelSmall.copyWith(
            color: AppTheme.neonOrange,
            fontSize: 10,
          ),
        ),
        const SizedBox(width: 8),
        Text(
          '↓${AppFormatter.formatBytes(app.rxBytes)}',
          style: AppTheme.labelSmall.copyWith(
            color: AppTheme.neonGreen,
            fontSize: 10,
          ),
        ),
      ],
    ),
  );

  String _fmt(DateTime t) =>
      '${t.hour.toString().padLeft(2, '0')}:'
      '${t.minute.toString().padLeft(2, '0')}';
}

// ── Monitor Toggle Card ──────────────────────────────────────────────────

class _MonitorToggleCard extends StatelessWidget {
  final bool active;
  final bool busy;
  final ValueChanged<bool> onChanged;
  const _MonitorToggleCard({
    required this.active,
    required this.busy,
    required this.onChanged,
  });

  @override
  Widget build(BuildContext context) {
    final color = active ? AppTheme.neonGreen : AppTheme.textMuted;
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: AppTheme.backgroundCard,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: color.withValues(alpha: 0.3)),
      ),
      child: Row(
        children: [
          Icon(
            active ? Icons.podcasts_rounded : Icons.podcasts_outlined,
            color: color,
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Real-Time Connection Monitor',
                  style: AppTheme.bodyMedium.copyWith(
                    fontWeight: FontWeight.w700,
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  active
                      ? 'Watching real connections via a local VPN'
                      : 'Uses a local VPN to see real remote IP/port per app — requires the system VPN permission',
                  style: AppTheme.bodyMedium.copyWith(
                    color: AppTheme.textMuted,
                    fontSize: 10,
                  ),
                ),
              ],
            ),
          ),
          if (busy)
            const SizedBox(
              width: 20,
              height: 20,
              child: CircularProgressIndicator(strokeWidth: 2),
            )
          else
            Switch(
              value: active,
              onChanged: onChanged,
              activeThumbColor: AppTheme.neonGreen,
            ),
        ],
      ),
    );
  }
}

// ── Filter Button ─────────────────────────────────────────────────────────

class _FilterBtn extends StatelessWidget {
  final String label;
  final int count;
  final bool active;
  final Color color;
  final VoidCallback onTap;
  const _FilterBtn({
    required this.label,
    required this.count,
    required this.active,
    required this.onTap,
    this.color = AppTheme.neonCyan,
  });

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
        decoration: BoxDecoration(
          color: active
              ? color.withValues(alpha: 0.15)
              : AppTheme.backgroundCard,
          borderRadius: BorderRadius.circular(4),
          border: Border.all(
            color: active ? color.withValues(alpha: 0.6) : AppTheme.borderColor,
          ),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              label,
              style: AppTheme.labelSmall.copyWith(
                color: active ? color : AppTheme.textMuted,
                fontSize: 9,
                letterSpacing: 0.8,
              ),
            ),
            const SizedBox(width: 5),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1),
              decoration: BoxDecoration(
                color: color.withValues(alpha: 0.15),
                borderRadius: BorderRadius.circular(8),
              ),
              child: Text(
                '$count',
                style: AppTheme.labelSmall.copyWith(color: color, fontSize: 8),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

// ── Connection Card ───────────────────────────────────────────────────────

class _ConnectionCard extends StatelessWidget {
  final ConnectionEvidence connection;
  final VoidCallback onTap;
  const _ConnectionCard({required this.connection, required this.onTap});

  Color get _color => switch (connection.assessment) {
    ConnectionAssessment.suspicious => AppTheme.alertOrange,
    ConnectionAssessment.investigate => AppTheme.neonCyan,
    ConnectionAssessment.normal => AppTheme.borderColor,
  };

  @override
  Widget build(BuildContext context) {
    final c = connection;
    return GestureDetector(
      onTap: onTap,
      child: Container(
        margin: const EdgeInsets.only(bottom: 8),
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: AppTheme.backgroundCard,
          borderRadius: BorderRadius.circular(8),
          border: Border(
            left: BorderSide(color: _color, width: 2.5),
            top: BorderSide(color: AppTheme.borderColor),
            right: BorderSide(color: AppTheme.borderColor),
            bottom: BorderSide(color: AppTheme.borderColor),
          ),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Expanded(
                  child: Text(
                    c.appName,
                    style: AppTheme.bodyMedium.copyWith(
                      fontWeight: FontWeight.w700,
                    ),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
                if (c.isActive)
                  Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 5,
                      vertical: 1,
                    ),
                    decoration: BoxDecoration(
                      color: AppTheme.neonGreen.withValues(alpha: 0.15),
                      borderRadius: BorderRadius.circular(3),
                    ),
                    child: Text(
                      'ACTIVE',
                      style: AppTheme.labelSmall.copyWith(
                        color: AppTheme.neonGreen,
                        fontSize: 8,
                      ),
                    ),
                  ),
                if (c.assessment != ConnectionAssessment.normal) ...[
                  const SizedBox(width: 6),
                  Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 5,
                      vertical: 1,
                    ),
                    decoration: BoxDecoration(
                      color: _color.withValues(alpha: 0.15),
                      borderRadius: BorderRadius.circular(3),
                    ),
                    child: Text(
                      c.assessment.label,
                      style: AppTheme.labelSmall.copyWith(
                        color: _color,
                        fontSize: 8,
                      ),
                    ),
                  ),
                ],
              ],
            ),
            const SizedBox(height: 4),
            Text(
              '${c.remoteAddress}:${c.remotePort}  ·  ${c.protocol}',
              style: AppTheme.bodyMedium.copyWith(
                color: AppTheme.textSecondary,
                fontSize: 11,
              ),
            ),
            const SizedBox(height: 4),
            Row(
              children: [
                Text(
                  c.isPersistent ? 'Persistent' : 'One-off',
                  style: AppTheme.labelSmall.copyWith(
                    color: c.isPersistent
                        ? AppTheme.neonCyan
                        : AppTheme.textMuted,
                    fontSize: 9,
                  ),
                ),
                const SizedBox(width: 10),
                Text(
                  '${AppFormatter.formatBytes(c.bytesSent)} sent',
                  style: AppTheme.labelSmall.copyWith(
                    color: AppTheme.textMuted,
                    fontSize: 9,
                  ),
                ),
                const SizedBox(width: 10),
                Text(
                  AppFormatter.formatTimeAgo(c.lastSeen),
                  style: AppTheme.labelSmall.copyWith(
                    color: AppTheme.textMuted,
                    fontSize: 9,
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

// ── Connection Detail Sheet ───────────────────────────────────────────────

class _ConnectionDetailSheet extends StatelessWidget {
  final ConnectionEvidence connection;
  const _ConnectionDetailSheet({required this.connection});

  @override
  Widget build(BuildContext context) {
    final c = connection;
    return SafeArea(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'CONNECTION DETAILS',
              style: AppTheme.labelSmall.copyWith(
                color: AppTheme.neonCyan,
                letterSpacing: 1.5,
              ),
            ),
            const SizedBox(height: 12),
            _row('Process', '${c.appName} (${c.packageName})'),
            _row('Remote Endpoint', '${c.remoteAddress}:${c.remotePort}'),
            _row('Protocol', c.protocol),
            _row('First Observed', _time(c.firstSeen)),
            _row('Last Observed', _time(c.lastSeen)),
            _row(
              'Connection Pattern',
              c.isPersistent ? 'Persistent' : 'One-off',
            ),
            _row('Reconnections', '${c.reconnectCount}'),
            _row('Data', '↑${_bytes(c.bytesSent)}  ↓${_bytes(c.bytesReceived)}'),
            const SizedBox(height: 10),
            Text(
              'Assessment: ${c.assessment.label}',
              style: AppTheme.bodyMedium.copyWith(fontWeight: FontWeight.w700),
            ),
            if (c.reasons.isNotEmpty) ...[
              const SizedBox(height: 6),
              ...c.reasons.map(
                (r) => Padding(
                  padding: const EdgeInsets.only(bottom: 4),
                  child: Text(
                    '• $r',
                    style: AppTheme.bodyMedium.copyWith(
                      color: AppTheme.textSecondary,
                      fontSize: 11,
                    ),
                  ),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }

  String _bytes(int b) => AppFormatter.formatBytes(b);
  String _time(DateTime t) =>
      '${t.hour.toString().padLeft(2, '0')}:${t.minute.toString().padLeft(2, '0')}:${t.second.toString().padLeft(2, '0')}';

  Widget _row(String label, String value) => Padding(
    padding: const EdgeInsets.symmetric(vertical: 4),
    child: Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SizedBox(
          width: 130,
          child: Text(
            label,
            style: AppTheme.bodyMedium.copyWith(color: AppTheme.textMuted),
          ),
        ),
        Expanded(child: Text(value, style: AppTheme.bodyMedium)),
      ],
    ),
  );
}

// ── Data Models ───────────────────────────────────────────────────────────

enum _ConnFilter { all, active, suspicious }

class _AppTraffic {
  final String pkg, name;
  final int txBytes, rxBytes;

  const _AppTraffic({
    required this.pkg,
    required this.name,
    required this.txBytes,
    required this.rxBytes,
  });
}
