import 'package:flutter/material.dart';
import 'package:rat3/core/theme/app_theme.dart';
import 'package:rat3/core/utils/app_utils.dart';
import 'package:rat3/data/services/platform_channel_service.dart';

/// NetworkScreen
///
/// Responsibility: Show every user-installed app's network usage —
/// how much data each app has SENT and RECEIVED since last boot.
///
/// This screen is SELF-CONTAINED — it fetches its own data via
/// PlatformChannelService directly. It does NOT depend on the scan
/// cycle or AppController.connections, so it always shows real data.
///
/// Data source: TrafficStats per-UID (Android API, always available).
///
/// Each app entry shows:
///   • App name + package name
///   • Total bytes SENT (TX) — highlighted red if large
///   • Total bytes RECEIVED (RX)
///   • A risk tag: HIGH UPLOADER / SUSPICIOUS if TX is large
///
/// Sorted by TX bytes descending (biggest senders first) —
/// because data exfiltration = sending, not receiving.
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

  // Filter state
  _Filter _filter = _Filter.all;

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
    'com.example.rat3',
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
      final raw = await _platform.getAppNetworkUsage();

      final apps = <_AppTraffic>[];
      for (final r in raw) {
        final pkg = r['packageName'] as String? ?? '';
        final name = r['appName'] as String? ?? pkg;
        final tx = (r['txBytes'] as num?)?.toInt() ?? 0;
        final rx = (r['rxBytes'] as num?)?.toInt() ?? 0;
        if (_skip(pkg)) continue;
        // Include ALL apps — even those with 0 bytes (still useful to show)
        apps.add(_AppTraffic(pkg: pkg, name: name, txBytes: tx, rxBytes: rx));
      }

      // Sort by TX descending — biggest uploaders first
      apps.sort((a, b) => b.txBytes.compareTo(a.txBytes));

      setState(() {
        _apps = apps;
        _lastLoaded = DateTime.now();
        _loading = false;
      });
    } catch (e) {
      setState(() {
        _error = e.toString();
        _loading = false;
      });
    }
  }

  List<_AppTraffic> get _filtered {
    switch (_filter) {
      case _Filter.all:
        return _apps;
      case _Filter.senders:
        return _apps.where((a) => a.txBytes > 0).toList();
      case _Filter.highRisk:
        return _apps.where((a) => a.riskTag != _RiskTag.none).toList();
    }
  }

  @override
  Widget build(BuildContext context) {
    final filtered = _filtered;

    // Summary totals
    final totalTx = _apps.fold<int>(0, (s, a) => s + a.txBytes);
    final totalRx = _apps.fold<int>(0, (s, a) => s + a.rxBytes);
    final highCount = _apps.where((a) => a.riskTag == _RiskTag.high).length;
    final suspCount = _apps
        .where((a) => a.riskTag == _RiskTag.suspicious)
        .length;

    return Scaffold(
      backgroundColor: AppTheme.backgroundPrimary,
      body: Column(
        children: [
          // ── Header ─────────────────────────────────────────────────────
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 16, 16, 0),
            child: Row(
              children: [
                Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'NETWORK USAGE',
                      style: AppTheme.labelSmall.copyWith(
                        color: AppTheme.neonCyan,
                        letterSpacing: 2,
                        fontSize: 11,
                        fontWeight: FontWeight.w800,
                      ),
                    ),
                    if (_lastLoaded != null)
                      Text(
                        'since last boot  •  ${_fmt(_lastLoaded!)}',
                        style: AppTheme.bodyMedium.copyWith(
                          color: AppTheme.textMuted,
                          fontSize: 9,
                        ),
                      ),
                  ],
                ),
                const Spacer(),
                if (_loading)
                  const SizedBox(
                    width: 18,
                    height: 18,
                    child: CircularProgressIndicator(
                      strokeWidth: 2,
                      color: AppTheme.neonGreen,
                    ),
                  )
                else
                  GestureDetector(
                    onTap: _load,
                    child: Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 10,
                        vertical: 5,
                      ),
                      decoration: BoxDecoration(
                        color: AppTheme.neonGreen.withValues(alpha: 0.1),
                        borderRadius: BorderRadius.circular(4),
                        border: Border.all(
                          color: AppTheme.neonGreen.withValues(alpha: 0.4),
                        ),
                      ),
                      child: Row(
                        children: [
                          const Icon(
                            Icons.refresh_rounded,
                            size: 13,
                            color: AppTheme.neonGreen,
                          ),
                          const SizedBox(width: 4),
                          Text(
                            'REFRESH',
                            style: AppTheme.labelSmall.copyWith(
                              color: AppTheme.neonGreen,
                              fontSize: 9,
                              letterSpacing: 1,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
              ],
            ),
          ),

          // ── Summary cards ───────────────────────────────────────────────
          if (!_loading && _error == null && _apps.isNotEmpty)
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 14, 16, 0),
              child: Row(
                children: [
                  _SummaryCard(
                    icon: Icons.arrow_upward_rounded,
                    label: 'TOTAL SENT',
                    value: AppFormatter.formatBytes(totalTx),
                    color: highCount > 0
                        ? AppTheme.alertRed
                        : AppTheme.neonOrange,
                  ),
                  const SizedBox(width: 8),
                  _SummaryCard(
                    icon: Icons.arrow_downward_rounded,
                    label: 'TOTAL RECV',
                    value: AppFormatter.formatBytes(totalRx),
                    color: AppTheme.neonGreen,
                  ),
                  const SizedBox(width: 8),
                  _SummaryCard(
                    icon: Icons.warning_amber_rounded,
                    label: 'FLAGGED',
                    value: '${highCount + suspCount} apps',
                    color: highCount > 0
                        ? AppTheme.alertRed
                        : suspCount > 0
                        ? AppTheme.alertOrange
                        : AppTheme.textMuted,
                  ),
                ],
              ),
            ),

          // ── Filter bar ──────────────────────────────────────────────────
          if (!_loading && _error == null && _apps.isNotEmpty)
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 12, 16, 0),
              child: Row(
                children: [
                  _FilterBtn(
                    label: 'ALL APPS',
                    count: _apps.length,
                    active: _filter == _Filter.all,
                    onTap: () => setState(() => _filter = _Filter.all),
                  ),
                  const SizedBox(width: 8),
                  _FilterBtn(
                    label: 'SENT DATA',
                    count: _apps.where((a) => a.txBytes > 0).length,
                    active: _filter == _Filter.senders,
                    onTap: () => setState(() => _filter = _Filter.senders),
                  ),
                  const SizedBox(width: 8),
                  _FilterBtn(
                    label: 'FLAGGED',
                    count: highCount + suspCount,
                    active: _filter == _Filter.highRisk,
                    color: AppTheme.alertOrange,
                    onTap: () => setState(() => _filter = _Filter.highRisk),
                  ),
                ],
              ),
            ),

          const SizedBox(height: 10),

          // ── Body ────────────────────────────────────────────────────────
          Expanded(
            child: _error != null
                ? _buildError()
                : _loading
                ? _buildLoading()
                : _apps.isEmpty
                ? _buildEmpty()
                : filtered.isEmpty
                ? _buildNoMatch()
                : _buildList(filtered),
          ),
        ],
      ),
    );
  }

  Widget _buildList(List<_AppTraffic> apps) {
    return ListView.builder(
      padding: const EdgeInsets.fromLTRB(16, 4, 16, 100),
      itemCount: apps.length,
      itemBuilder: (_, i) => _AppTile(app: apps[i]),
    );
  }

  Widget _buildLoading() => const Center(
    child: Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        CircularProgressIndicator(strokeWidth: 2, color: AppTheme.neonGreen),
        SizedBox(height: 16),
        Text(
          'Reading network usage…',
          style: TextStyle(color: AppTheme.textMuted, fontSize: 12),
        ),
      ],
    ),
  );

  Widget _buildEmpty() => Center(
    child: Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        Container(
          padding: const EdgeInsets.all(20),
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            color: AppTheme.neonGreen.withValues(alpha: 0.08),
            border: Border.all(
              color: AppTheme.neonGreen.withValues(alpha: 0.3),
            ),
          ),
          child: const Icon(
            Icons.wifi_off_rounded,
            size: 36,
            color: AppTheme.neonGreen,
          ),
        ),
        const SizedBox(height: 16),
        const Text(
          'No network usage data found',
          style: TextStyle(color: AppTheme.textMuted),
        ),
        const SizedBox(height: 6),
        const Text(
          'Try refreshing after using some apps',
          style: TextStyle(color: AppTheme.textMuted, fontSize: 11),
        ),
      ],
    ),
  );

  Widget _buildNoMatch() => const Center(
    child: Text(
      'No apps match this filter',
      style: TextStyle(color: AppTheme.textMuted),
    ),
  );

  Widget _buildError() => Center(
    child: Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        const Icon(Icons.error_outline, color: AppTheme.alertRed, size: 40),
        const SizedBox(height: 12),
        Text(
          _error ?? '',
          style: const TextStyle(color: AppTheme.textMuted),
          textAlign: TextAlign.center,
        ),
        const SizedBox(height: 16),
        GestureDetector(
          onTap: _load,
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 10),
            decoration: BoxDecoration(
              border: Border.all(
                color: AppTheme.neonGreen.withValues(alpha: 0.5),
              ),
              borderRadius: BorderRadius.circular(4),
            ),
            child: const Text(
              'RETRY',
              style: TextStyle(
                color: AppTheme.neonGreen,
                letterSpacing: 1.5,
                fontSize: 11,
              ),
            ),
          ),
        ),
      ],
    ),
  );

  String _fmt(DateTime t) =>
      '${t.hour.toString().padLeft(2, '0')}:'
      '${t.minute.toString().padLeft(2, '0')}';
}

// ── Summary Card ──────────────────────────────────────────────────────────

class _SummaryCard extends StatelessWidget {
  final IconData icon;
  final String label, value;
  final Color color;
  const _SummaryCard({
    required this.icon,
    required this.label,
    required this.value,
    required this.color,
  });

  @override
  Widget build(BuildContext context) {
    return Expanded(
      child: Container(
        padding: const EdgeInsets.all(10),
        decoration: BoxDecoration(
          color: AppTheme.backgroundCard,
          borderRadius: BorderRadius.circular(6),
          border: Border.all(color: color.withValues(alpha: 0.3)),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(icon, size: 10, color: color),
                const SizedBox(width: 4),
                Text(
                  label,
                  style: AppTheme.labelSmall.copyWith(
                    color: color,
                    fontSize: 8,
                    letterSpacing: 0.8,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 4),
            Text(
              value,
              style: AppTheme.bodyMedium.copyWith(
                color: AppTheme.textPrimary,
                fontWeight: FontWeight.w700,
                fontSize: 11,
              ),
              overflow: TextOverflow.ellipsis,
            ),
          ],
        ),
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

// ── App Traffic Tile ──────────────────────────────────────────────────────

class _AppTile extends StatelessWidget {
  final _AppTraffic app;
  const _AppTile({required this.app});

  @override
  Widget build(BuildContext context) {
    final tag = app.riskTag;

    Color leftBorderColor;
    if (tag == _RiskTag.high) {
      leftBorderColor = AppTheme.alertRed;
    } else if (tag == _RiskTag.suspicious) {
      leftBorderColor = AppTheme.alertOrange;
    } else if (app.txBytes > 0) {
      leftBorderColor = AppTheme.neonCyan.withValues(alpha: 0.4);
    } else {
      leftBorderColor = AppTheme.borderColor;
    }

    return Container(
      margin: const EdgeInsets.only(bottom: 7),
      decoration: BoxDecoration(
        color: AppTheme.backgroundCard,
        borderRadius: BorderRadius.circular(6),
        border: Border(
          left: BorderSide(color: leftBorderColor, width: 2.5),
          top: BorderSide(color: AppTheme.borderColor),
          right: BorderSide(color: AppTheme.borderColor),
          bottom: BorderSide(color: AppTheme.borderColor),
        ),
      ),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Row 1: name + risk badge
            Row(
              children: [
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        app.name,
                        style: AppTheme.bodyMedium.copyWith(
                          fontWeight: FontWeight.w700,
                          color: AppTheme.textPrimary,
                        ),
                        overflow: TextOverflow.ellipsis,
                      ),
                      Text(
                        app.pkg,
                        style: AppTheme.bodyMedium.copyWith(
                          color: AppTheme.textMuted,
                          fontSize: 9,
                        ),
                        overflow: TextOverflow.ellipsis,
                      ),
                    ],
                  ),
                ),
                if (tag != _RiskTag.none) _RiskBadge(tag: tag),
              ],
            ),

            const SizedBox(height: 8),

            // Row 2: TX / RX chips
            Row(
              children: [
                _DataChip(
                  icon: Icons.arrow_upward_rounded,
                  label: 'SENT',
                  value: AppFormatter.formatBytes(app.txBytes),
                  color: app.txBytes > 10 * 1024 * 1024
                      ? AppTheme.alertRed
                      : app.txBytes > 1024 * 1024
                      ? AppTheme.alertOrange
                      : AppTheme.textMuted,
                ),
                const SizedBox(width: 12),
                _DataChip(
                  icon: Icons.arrow_downward_rounded,
                  label: 'RECV',
                  value: AppFormatter.formatBytes(app.rxBytes),
                  color: AppTheme.neonGreen,
                ),
                const Spacer(),
                // TX bar visualiser
                if (app.txBytes > 0) _TxBar(txBytes: app.txBytes),
              ],
            ),

            // Warning for large uploads
            if (tag == _RiskTag.high) ...[
              const SizedBox(height: 6),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 5),
                decoration: BoxDecoration(
                  color: AppTheme.alertRed.withValues(alpha: 0.07),
                  borderRadius: BorderRadius.circular(4),
                  border: Border.all(
                    color: AppTheme.alertRed.withValues(alpha: 0.25),
                  ),
                ),
                child: Row(
                  children: [
                    const Icon(
                      Icons.warning_amber_rounded,
                      size: 12,
                      color: AppTheme.alertRed,
                    ),
                    const SizedBox(width: 6),
                    Expanded(
                      child: Text(
                        'Large data upload — ${AppFormatter.formatBytes(app.txBytes)} sent. '
                        'Verify this is expected.',
                        style: AppTheme.bodyMedium.copyWith(
                          color: AppTheme.alertRed,
                          fontSize: 10,
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ] else if (tag == _RiskTag.suspicious) ...[
              const SizedBox(height: 6),
              Row(
                children: [
                  const Icon(
                    Icons.info_outline,
                    size: 12,
                    color: AppTheme.alertOrange,
                  ),
                  const SizedBox(width: 6),
                  Expanded(
                    child: Text(
                      'Elevated outbound data — review if expected.',
                      style: AppTheme.bodyMedium.copyWith(
                        color: AppTheme.alertOrange,
                        fontSize: 10,
                      ),
                    ),
                  ),
                ],
              ),
            ],
          ],
        ),
      ),
    );
  }
}

// ── TX Bar Visualiser ─────────────────────────────────────────────────────

class _TxBar extends StatelessWidget {
  final int txBytes;
  const _TxBar({required this.txBytes});

  @override
  Widget build(BuildContext context) {
    // Max reference = 100 MB
    const maxBytes = 100 * 1024 * 1024;
    final ratio = (txBytes / maxBytes).clamp(0.0, 1.0);
    final color = txBytes > 10 * 1024 * 1024
        ? AppTheme.alertRed
        : txBytes > 1024 * 1024
        ? AppTheme.alertOrange
        : AppTheme.neonCyan;

    return SizedBox(
      width: 60,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.end,
        children: [
          Text(
            AppFormatter.formatBytes(txBytes),
            style: AppTheme.labelSmall.copyWith(color: color, fontSize: 8),
          ),
          const SizedBox(height: 3),
          ClipRRect(
            borderRadius: BorderRadius.circular(2),
            child: LinearProgressIndicator(
              value: ratio,
              minHeight: 4,
              backgroundColor: AppTheme.borderColor,
              valueColor: AlwaysStoppedAnimation(color),
            ),
          ),
        ],
      ),
    );
  }
}

// ── Data Chip ─────────────────────────────────────────────────────────────

class _DataChip extends StatelessWidget {
  final IconData icon;
  final String label, value;
  final Color color;
  const _DataChip({
    required this.icon,
    required this.label,
    required this.value,
    required this.color,
  });

  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Icon(icon, size: 10, color: color),
        const SizedBox(width: 3),
        Text(
          '$label  ',
          style: AppTheme.labelSmall.copyWith(
            color: AppTheme.textMuted,
            fontSize: 9,
          ),
        ),
        Text(
          value,
          style: AppTheme.labelSmall.copyWith(
            color: color,
            fontWeight: FontWeight.w700,
            fontSize: 10,
          ),
        ),
      ],
    );
  }
}

// ── Risk Badge ────────────────────────────────────────────────────────────

class _RiskBadge extends StatelessWidget {
  final _RiskTag tag;
  const _RiskBadge({required this.tag});

  @override
  Widget build(BuildContext context) {
    final color = tag == _RiskTag.high
        ? AppTheme.alertRed
        : AppTheme.alertOrange;
    final label = tag == _RiskTag.high ? 'HIGH UPLOAD' : 'ELEVATED';
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 3),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(3),
        border: Border.all(color: color.withValues(alpha: 0.4)),
      ),
      child: Text(
        label,
        style: AppTheme.labelSmall.copyWith(
          color: color,
          fontSize: 8,
          fontWeight: FontWeight.w800,
        ),
      ),
    );
  }
}

// ── Data Models ───────────────────────────────────────────────────────────

enum _Filter { all, senders, highRisk }

enum _RiskTag { none, suspicious, high }

class _AppTraffic {
  final String pkg, name;
  final int txBytes, rxBytes;

  const _AppTraffic({
    required this.pkg,
    required this.name,
    required this.txBytes,
    required this.rxBytes,
  });

  int get totalBytes => txBytes + rxBytes;

  // > 50 MB sent = HIGH, > 5 MB = suspicious
  _RiskTag get riskTag {
    if (txBytes > 50 * 1024 * 1024) return _RiskTag.high;
    if (txBytes > 5 * 1024 * 1024) return _RiskTag.suspicious;
    return _RiskTag.none;
  }
}
