import 'dart:async';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:rat3/core/theme/app_theme.dart';
import 'package:rat3/core/utils/app_utils.dart';
import 'package:rat3/data/models/app_models.dart';
import 'package:rat3/data/services/app_controller.dart';
import 'package:rat3/data/services/app_scanner_service.dart';
import 'package:rat3/data/services/platform_channel_service.dart';
import 'package:rat3/widgets/common_widgets.dart';

// ─────────────────────────────────────────────────────────────────────────────
//  AppScanScreen — Application Assessment
//
//  Entry point: navigated to when user taps "SCAN ALL APPS" button.
//
//  Flow:
//    1. Screen opens → scan starts automatically
//    2. Progress bar + live status message shown while Kotlin scans
//    3. Results page shown: Malicious Indicators / Suspicious / Needs Review /
//       Trusted tabs — each app's verdict comes with an explainable evidence
//       list (see AppScannerService's doc comment). An app is never flagged
//       for holding permissions, using the network, or running in the
//       background alone — see MainActivity.handleScanAllApps in the native
//       layer for the actual evidence/correlation rules.
//    4. Tapping an app shows the full evidence detail sheet.
// ─────────────────────────────────────────────────────────────────────────────

Color trustColor(AppTrustLevel l) => switch (l) {
  AppTrustLevel.maliciousIndicators => AppTheme.alertRed,
  AppTrustLevel.suspicious => AppTheme.alertOrange,
  AppTrustLevel.needsReview => AppTheme.neonCyan,
  AppTrustLevel.trusted => AppTheme.neonGreen,
  AppTrustLevel.unknown => AppTheme.textMuted,
};

IconData trustIcon(AppTrustLevel l) => switch (l) {
  AppTrustLevel.maliciousIndicators => Icons.dangerous_rounded,
  AppTrustLevel.suspicious => Icons.warning_amber_rounded,
  AppTrustLevel.needsReview => Icons.search_rounded,
  AppTrustLevel.trusted => Icons.verified_rounded,
  AppTrustLevel.unknown => Icons.help_outline_rounded,
};

class AppScanScreen extends StatefulWidget {
  const AppScanScreen({super.key});

  @override
  State<AppScanScreen> createState() => _AppScanScreenState();
}

class _AppScanScreenState extends State<AppScanScreen>
    with SingleTickerProviderStateMixin {
  late final AppScannerService _scanner;
  late final TabController _tabCtrl;

  double _progress = 0.0;
  String _statusMsg = 'Preparing scan…';
  bool _scanning = true;
  AppScanResult? _result;
  String? _error;

  final List<StreamSubscription> _subs = [];

  @override
  void initState() {
    super.initState();
    _tabCtrl = TabController(length: 4, vsync: this);
    _scanner = AppScannerService(platform: PlatformChannelService());

    _subs.add(
      _scanner.progress.listen((p) {
        if (mounted) setState(() => _progress = p);
      }),
    );
    _subs.add(
      _scanner.status.listen((s) {
        if (mounted) setState(() => _statusMsg = s);
      }),
    );

    // Auto-start scan as soon as screen opens
    _startScan();
  }

  Future<void> _startScan() async {
    setState(() {
      _scanning = true;
      _error = null;
      _result = null;
      _progress = 0;
    });
    try {
      final result = await _scanner.runFullScan();
      if (!mounted) return;
      setState(() {
        _result = result;
        _scanning = false;
      });
      // Surface the per-app findings in the shared Alerts tab.
      final controller = context.read<AppController>();
      controller.alertEngine.injectAppScanAlerts(result.alerts);
      // Let the Connection Monitor correlate a connection with an app this
      // scan already flagged, instead of judging network activity alone.
      controller.updateUntrustedPackages([
        ...result.maliciousApps,
        ...result.suspiciousApps,
        ...result.needsReviewApps,
      ]);
    } catch (e) {
      if (mounted) {
        setState(() {
          _error = e.toString();
          _scanning = false;
        });
      }
    }
  }

  @override
  void dispose() {
    for (final s in _subs) {
      s.cancel();
    }
    _scanner.dispose();
    _tabCtrl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppTheme.backgroundPrimary,
      appBar: AppBar(
        backgroundColor: AppTheme.backgroundPrimary,
        leading: IconButton(
          icon: const Icon(
            Icons.arrow_back_ios,
            color: AppTheme.neonGreen,
            size: 18,
          ),
          onPressed: () => Navigator.of(context).pop(),
        ),
        title: Row(
          children: [
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
              decoration: BoxDecoration(
                color: AppTheme.neonGreen.withValues(alpha: 0.15),
                borderRadius: BorderRadius.circular(4),
                border: Border.all(
                  color: AppTheme.neonGreen.withValues(alpha: 0.4),
                ),
              ),
              child: Text(
                'APP ASSESSMENT',
                style: AppTheme.labelSmall.copyWith(
                  color: AppTheme.neonGreen,
                  letterSpacing: 2,
                ),
              ),
            ),
          ],
        ),
        actions: [
          if (!_scanning)
            IconButton(
              icon: const Icon(Icons.refresh, color: AppTheme.neonGreen),
              tooltip: 'Re-scan',
              onPressed: _startScan,
            ),
        ],
        bottom: _scanning
            ? null
            : TabBar(
                controller: _tabCtrl,
                isScrollable: true,
                labelColor: AppTheme.neonGreen,
                unselectedLabelColor: AppTheme.textMuted,
                indicatorColor: AppTheme.neonGreen,
                labelStyle: AppTheme.labelSmall,
                tabs: [
                  Tab(
                    text:
                        'MALICIOUS INDICATORS (${_result?.maliciousApps.length ?? 0})',
                  ),
                  Tab(
                    text: 'SUSPICIOUS (${_result?.suspiciousApps.length ?? 0})',
                  ),
                  Tab(
                    text:
                        'NEEDS REVIEW (${_result?.needsReviewApps.length ?? 0})',
                  ),
                  Tab(text: 'TRUSTED (${_result?.trustedApps.length ?? 0})'),
                ],
              ),
      ),
      body: _scanning
          ? _buildScanningView()
          : _error != null
          ? _buildErrorView()
          : _buildResultsView(),
    );
  }

  // ── Scanning Progress View ─────────────────────────────────────────────────

  Widget _buildScanningView() {
    return Padding(
      padding: const EdgeInsets.all(24),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          // Animated scanner icon
          TweenAnimationBuilder<double>(
            tween: Tween(begin: 0.8, end: 1.1),
            duration: const Duration(milliseconds: 800),
            builder: (_, scale, child) =>
                Transform.scale(scale: scale, child: child),
            child: Container(
              width: 100,
              height: 100,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: AppTheme.neonGreen.withValues(alpha: 0.1),
                border: Border.all(
                  color: AppTheme.neonGreen.withValues(alpha: 0.5),
                  width: 2,
                ),
                boxShadow: [
                  BoxShadow(
                    color: AppTheme.neonGreen.withValues(alpha: 0.2),
                    blurRadius: 20,
                    spreadRadius: 5,
                  ),
                ],
              ),
              child: const Icon(
                Icons.security_rounded,
                color: AppTheme.neonGreen,
                size: 48,
              ),
            ),
          ),
          const SizedBox(height: 40),

          // Progress bar
          ClipRRect(
            borderRadius: BorderRadius.circular(4),
            child: LinearProgressIndicator(
              value: _progress,
              minHeight: 8,
              backgroundColor: AppTheme.borderColor,
              valueColor: const AlwaysStoppedAnimation(AppTheme.neonGreen),
            ),
          ),
          const SizedBox(height: 12),

          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Text('Scanning apps…', style: AppTheme.bodyMedium),
              Text(
                '${(_progress * 100).toInt()}%',
                style: AppTheme.bodyLarge.copyWith(color: AppTheme.neonGreen),
              ),
            ],
          ),
          const SizedBox(height: 24),

          // Live status message
          AnimatedSwitcher(
            duration: const Duration(milliseconds: 300),
            child: Text(
              _statusMsg,
              key: ValueKey(_statusMsg),
              style: AppTheme.bodyMedium.copyWith(color: AppTheme.neonGreen),
              textAlign: TextAlign.center,
            ),
          ),
          const SizedBox(height: 40),

          // Step checklist
          ..._buildStepList(),
        ],
      ),
    );
  }

  static const _steps = [
    (0.1, 'Reading installed applications'),
    (0.4, 'Evaluating evidence for each app'),
    (0.55, 'Reading network data usage per app'),
    (0.70, 'Enumerating device sensors'),
    (0.85, 'Generating security alerts'),
    (1.0, 'Finalizing results'),
  ];

  List<Widget> _buildStepList() => _steps.map((step) {
    final (threshold, label) = step;
    final done = _progress >= threshold;
    final active = _progress >= threshold - 0.15 && _progress < threshold;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        children: [
          SizedBox(
            width: 20,
            height: 20,
            child: done
                ? const Icon(
                    Icons.check_circle,
                    size: 16,
                    color: AppTheme.neonGreen,
                  )
                : active
                ? const SizedBox(
                    width: 14,
                    height: 14,
                    child: CircularProgressIndicator(
                      strokeWidth: 2,
                      color: AppTheme.neonGreen,
                    ),
                  )
                : Container(
                    width: 8,
                    height: 8,
                    margin: const EdgeInsets.all(4),
                    decoration: const BoxDecoration(
                      shape: BoxShape.circle,
                      color: AppTheme.textMuted,
                    ),
                  ),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              label,
              style: AppTheme.bodyMedium.copyWith(
                color: done || active
                    ? AppTheme.textPrimary
                    : AppTheme.textMuted,
              ),
            ),
          ),
        ],
      ),
    );
  }).toList();

  // ── Error View ─────────────────────────────────────────────────────────────

  Widget _buildErrorView() => Center(
    child: Padding(
      padding: const EdgeInsets.all(24),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const Icon(Icons.error_outline, color: AppTheme.alertRed, size: 56),
          const SizedBox(height: 16),
          Text(
            'Scan Failed',
            style: AppTheme.bodyLarge.copyWith(
              color: AppTheme.alertRed,
              fontWeight: FontWeight.w700,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            _error ?? '',
            style: AppTheme.bodyMedium,
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 24),
          ElevatedButton(
            onPressed: _startScan,
            style: ElevatedButton.styleFrom(
              backgroundColor: AppTheme.neonGreen,
            ),
            child: Text(
              'RETRY',
              style: AppTheme.labelSmall.copyWith(
                color: AppTheme.backgroundPrimary,
                fontWeight: FontWeight.w700,
              ),
            ),
          ),
        ],
      ),
    ),
  );

  // ── Results View ───────────────────────────────────────────────────────────

  Widget _buildResultsView() {
    final r = _result!;
    return Column(
      children: [
        // Summary header
        _buildSummaryHeader(r),

        // Tab content
        Expanded(
          child: TabBarView(
            controller: _tabCtrl,
            children: [
              _AppListTab(
                apps: r.maliciousApps,
                level: AppTrustLevel.maliciousIndicators,
                netUsage: r.networkUsage,
              ),
              _AppListTab(
                apps: r.suspiciousApps,
                level: AppTrustLevel.suspicious,
                netUsage: r.networkUsage,
              ),
              _AppListTab(
                apps: r.needsReviewApps,
                level: AppTrustLevel.needsReview,
                netUsage: r.networkUsage,
              ),
              _AppListTab(
                apps: r.trustedApps,
                level: AppTrustLevel.trusted,
                netUsage: r.networkUsage,
              ),
            ],
          ),
        ),
      ],
    );
  }

  Widget _buildSummaryHeader(AppScanResult r) {
    return Container(
      padding: const EdgeInsets.fromLTRB(16, 12, 16, 12),
      color: AppTheme.backgroundSecondary,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              _summaryChip(
                r.maliciousApps.length.toString(),
                'MALICIOUS',
                AppTheme.alertRed,
              ),
              const SizedBox(width: 8),
              _summaryChip(
                r.suspiciousApps.length.toString(),
                'SUSPICIOUS',
                AppTheme.alertOrange,
              ),
              const SizedBox(width: 8),
              _summaryChip(
                r.needsReviewApps.length.toString(),
                'REVIEW',
                AppTheme.neonCyan,
              ),
              const SizedBox(width: 8),
              _summaryChip(
                r.trustedApps.length.toString(),
                'TRUSTED',
                AppTheme.neonGreen,
              ),
              const Spacer(),
              Column(
                crossAxisAlignment: CrossAxisAlignment.end,
                children: [
                  Text(
                    '${r.totalApps} apps scanned',
                    style: AppTheme.labelSmall.copyWith(
                      color: AppTheme.textMuted,
                    ),
                  ),
                  Text(
                    AppFormatter.formatTimeAgo(r.scannedAt),
                    style: AppTheme.labelSmall.copyWith(
                      color: AppTheme.textMuted,
                    ),
                  ),
                ],
              ),
            ],
          ),
          if (r.maliciousApps.isEmpty && r.suspiciousApps.isEmpty) ...[
            const SizedBox(height: 8),
            Text(
              r.needsReviewApps.isEmpty
                  ? 'No strong indicators of RAT malware were found among the apps RAT3 can inspect.'
                  : '${r.needsReviewApps.length} app(s) are worth a quick look — see the REVIEW tab.',
              style: AppTheme.labelSmall.copyWith(color: AppTheme.textMuted),
            ),
          ],
        ],
      ),
    );
  }

  Widget _summaryChip(String count, String label, Color color) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
    decoration: BoxDecoration(
      color: color.withValues(alpha: 0.12),
      borderRadius: BorderRadius.circular(6),
      border: Border.all(color: color.withValues(alpha: 0.4)),
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
          style: AppTheme.labelSmall.copyWith(
            color: color,
            fontSize: 9,
            letterSpacing: 1,
          ),
        ),
      ],
    ),
  );
}

// ─────────────────────────────────────────────────────────────────────────────
//  _AppListTab — shows list of apps for one trust category
// ─────────────────────────────────────────────────────────────────────────────

class _AppListTab extends StatelessWidget {
  final List<ScannedApp> apps;
  final AppTrustLevel level;
  final List<AppNetworkUsage> netUsage;

  const _AppListTab({
    required this.apps,
    required this.level,
    required this.netUsage,
  });

  @override
  Widget build(BuildContext context) {
    if (apps.isEmpty) {
      final emptyText = switch (level) {
        AppTrustLevel.maliciousIndicators =>
          'No apps matched a known-malicious indicator',
        AppTrustLevel.suspicious => 'No apps show suspicious indicators',
        AppTrustLevel.needsReview => 'No apps need a closer look',
        AppTrustLevel.trusted || AppTrustLevel.unknown =>
          'No apps in this category',
      };
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              Icons.check_circle_outline,
              color: AppTheme.neonGreen.withValues(alpha: 0.4),
              size: 56,
            ),
            const SizedBox(height: 12),
            Text(
              emptyText,
              style: AppTheme.bodyLarge.copyWith(color: AppTheme.textMuted),
              textAlign: TextAlign.center,
            ),
          ],
        ),
      );
    }

    // Build network usage lookup
    final netMap = <String, AppNetworkUsage>{};
    for (final n in netUsage) {
      netMap[n.packageName] = n;
    }

    return ListView.builder(
      padding: const EdgeInsets.symmetric(vertical: 8),
      itemCount: apps.length,
      itemBuilder: (ctx, i) => _AppTile(
        app: apps[i],
        netUsage: netMap[apps[i].packageName],
        onTap: () => _showDetail(ctx, apps[i], netMap[apps[i].packageName]),
      ),
    );
  }

  void _showDetail(BuildContext ctx, ScannedApp app, AppNetworkUsage? net) {
    showModalBottomSheet(
      context: ctx,
      isScrollControlled: true,
      backgroundColor: AppTheme.backgroundCard,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(16)),
      ),
      builder: (_) => _AppDetailSheet(app: app, netUsage: net),
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  _AppTile — single app row in the list
// ─────────────────────────────────────────────────────────────────────────────

class _AppTile extends StatelessWidget {
  final ScannedApp app;
  final AppNetworkUsage? netUsage;
  final VoidCallback onTap;

  const _AppTile({required this.app, this.netUsage, required this.onTap});

  @override
  Widget build(BuildContext context) {
    final color = trustColor(app.trustLevel);

    return GestureDetector(
      onTap: onTap,
      child: Container(
        margin: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: AppTheme.backgroundCard,
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: color.withValues(alpha: 0.3)),
        ),
        child: Row(
          children: [
            // Trust level icon
            Container(
              width: 44,
              height: 44,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: color.withValues(alpha: 0.12),
                border: Border.all(color: color.withValues(alpha: 0.5)),
              ),
              child: Icon(trustIcon(app.trustLevel), color: color, size: 20),
            ),
            const SizedBox(width: 12),

            // App info
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Expanded(
                        child: Text(
                          app.appName,
                          style: AppTheme.bodyLarge.copyWith(
                            fontWeight: FontWeight.w600,
                          ),
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                      if (app.isCurrentlyRunning)
                        Container(
                          margin: const EdgeInsets.only(left: 6),
                          padding: const EdgeInsets.symmetric(
                            horizontal: 5,
                            vertical: 1,
                          ),
                          decoration: BoxDecoration(
                            color: AppTheme.neonGreen.withValues(alpha: 0.15),
                            borderRadius: BorderRadius.circular(3),
                          ),
                          child: Text(
                            'IN USE',
                            style: AppTheme.labelSmall.copyWith(
                              color: AppTheme.neonGreen,
                              fontSize: 8,
                            ),
                          ),
                        ),
                    ],
                  ),
                  const SizedBox(height: 2),
                  Text(
                    app.packageName,
                    style: AppTheme.bodyMedium.copyWith(
                      fontSize: 10,
                      color: AppTheme.textMuted,
                    ),
                    overflow: TextOverflow.ellipsis,
                  ),
                  const SizedBox(height: 4),

                  // Why: trust reason (single, calm line — never "uninstall now")
                  Text(
                    app.trustReason,
                    style: AppTheme.bodyMedium.copyWith(
                      color: color.withValues(alpha: 0.85),
                      fontSize: 10,
                    ),
                    overflow: TextOverflow.ellipsis,
                    maxLines: 2,
                  ),

                  // Tags row
                  const SizedBox(height: 6),
                  Wrap(
                    spacing: 4,
                    runSpacing: 4,
                    children: [
                      if (app.isSideloaded)
                        _tag('NOT PLAY STORE', AppTheme.alertOrange),
                      if (app.isRecentInstall) _tag('NEW', AppTheme.neonCyan),
                      if (app.privateDataAccess.isNotEmpty)
                        _tag('PRIVATE DATA ACCESS', AppTheme.neonCyan),
                    ],
                  ),
                ],
              ),
            ),
            Icon(Icons.chevron_right, color: AppTheme.textMuted, size: 18),
          ],
        ),
      ),
    );
  }

  Widget _tag(String text, Color color) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 2),
    decoration: BoxDecoration(
      color: color.withValues(alpha: 0.12),
      borderRadius: BorderRadius.circular(3),
      border: Border.all(color: color.withValues(alpha: 0.4)),
    ),
    child: Text(
      text,
      style: AppTheme.labelSmall.copyWith(
        color: color,
        fontSize: 8,
        letterSpacing: 0.5,
      ),
    ),
  );
}

// ─────────────────────────────────────────────────────────────────────────────
//  _AppDetailSheet — full detail bottom sheet for a single app
// ─────────────────────────────────────────────────────────────────────────────

class _AppDetailSheet extends StatelessWidget {
  final ScannedApp app;
  final AppNetworkUsage? netUsage;

  const _AppDetailSheet({required this.app, this.netUsage});

  @override
  Widget build(BuildContext context) {
    final color = trustColor(app.trustLevel);

    return DraggableScrollableSheet(
      initialChildSize: 0.85,
      maxChildSize: 0.95,
      minChildSize: 0.5,
      expand: false,
      builder: (_, sc) => SingleChildScrollView(
        controller: sc,
        padding: const EdgeInsets.fromLTRB(16, 8, 16, 32),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Drag handle
            Center(
              child: Container(
                width: 40,
                height: 4,
                margin: const EdgeInsets.only(bottom: 16),
                decoration: BoxDecoration(
                  color: AppTheme.textMuted.withValues(alpha: 0.4),
                  borderRadius: BorderRadius.circular(2),
                ),
              ),
            ),

            // Header
            Row(
              children: [
                Container(
                  width: 52,
                  height: 52,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    color: color.withValues(alpha: 0.12),
                    border: Border.all(color: color.withValues(alpha: 0.5)),
                  ),
                  child: Icon(
                    trustIcon(app.trustLevel),
                    color: color,
                    size: 24,
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        app.appName,
                        style: AppTheme.bodyLarge.copyWith(
                          fontWeight: FontWeight.w700,
                          fontSize: 16,
                        ),
                      ),
                      Text(
                        app.packageName,
                        style: AppTheme.bodyMedium.copyWith(
                          color: AppTheme.textMuted,
                          fontSize: 11,
                        ),
                      ),
                      const SizedBox(height: 4),
                      Container(
                        padding: const EdgeInsets.symmetric(
                          horizontal: 8,
                          vertical: 3,
                        ),
                        decoration: BoxDecoration(
                          color: color.withValues(alpha: 0.15),
                          borderRadius: BorderRadius.circular(4),
                          border: Border.all(
                            color: color.withValues(alpha: 0.4),
                          ),
                        ),
                        child: Text(
                          app.trustLevel.label,
                          style: AppTheme.labelSmall.copyWith(
                            color: color,
                            letterSpacing: 1.5,
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),

            const SizedBox(height: 20),

            // Why RAT3 reached this assessment
            _sectionTitle('Assessment', Icons.fact_check_outlined, color),
            const SizedBox(height: 8),
            CyberCard(
              borderColor: color.withValues(alpha: 0.3),
              child: Text(
                app.trustReason,
                style: AppTheme.bodyMedium.copyWith(color: color),
              ),
            ),
            const SizedBox(height: 16),

            // Evidence (only present for non-trusted apps)
            if (app.evidence.isNotEmpty) ...[
              _sectionTitle('Why RAT3 flagged this', Icons.list_alt, color),
              const SizedBox(height: 8),
              ...app.evidence.map(
                (s) => Padding(
                  padding: const EdgeInsets.only(bottom: 6),
                  child: Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Icon(Icons.circle, size: 6, color: color),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          s,
                          style: AppTheme.bodyMedium.copyWith(
                            color: color.withValues(alpha: 0.9),
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 16),
            ],

            // Private Data Access — shown for every app that has one of these
            // channels, trusted or not, so the capability is always visible.
            if (app.privateDataAccess.isNotEmpty) ...[
              _sectionTitle(
                'Private Data Access',
                Icons.visibility_outlined,
                AppTheme.neonCyan,
              ),
              const SizedBox(height: 8),
              CyberCard(
                borderColor: AppTheme.neonCyan.withValues(alpha: 0.3),
                child: Column(
                  children: app.privateDataAccess
                      .map(
                        (s) => Padding(
                          padding: const EdgeInsets.symmetric(vertical: 4),
                          child: Row(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              const Icon(
                                Icons.remove_red_eye_outlined,
                                size: 14,
                                color: AppTheme.neonCyan,
                              ),
                              const SizedBox(width: 8),
                              Expanded(
                                child: Text(
                                  s,
                                  style: AppTheme.bodyMedium.copyWith(
                                    color: AppTheme.neonCyan,
                                  ),
                                ),
                              ),
                            ],
                          ),
                        ),
                      )
                      .toList(),
                ),
              ),
              const SizedBox(height: 16),
            ],

            // App info
            _sectionTitle(
              'App Information',
              Icons.info_outline,
              AppTheme.textSecondary,
            ),
            const SizedBox(height: 8),
            CyberCard(
              child: Column(
                children: [
                  _infoRow('Version', app.versionName),
                  _infoRow('Install Source', _sourceLabel(app.installSource)),
                  _infoRow('Installed', '${app.installDaysAgo} days ago'),
                  _infoRow('Target SDK', 'API ${app.targetSdkVersion}'),
                  _infoRow(
                    'Background Use',
                    '${app.backgroundTimeHrs.toStringAsFixed(1)}h today',
                  ),
                  _infoRow(
                    'Status',
                    app.isCurrentlyRunning
                        ? 'In foreground right now'
                        : 'Not in foreground',
                  ),
                ],
              ),
            ),

            const SizedBox(height: 16),

            // Network usage — supplementary info, never a trust signal on its own
            if (netUsage != null) ...[
              _sectionTitle('Network Usage', Icons.wifi, AppTheme.neonCyan),
              const SizedBox(height: 8),
              CyberCard(
                child: Column(
                  children: [
                    _infoRow(
                      'Data Sent',
                      AppFormatter.formatBytes(netUsage!.txBytes),
                    ),
                    _infoRow(
                      'Data Received',
                      AppFormatter.formatBytes(netUsage!.rxBytes),
                    ),
                    _infoRow(
                      'Total',
                      AppFormatter.formatBytes(netUsage!.totalBytes),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 16),
            ],

            // Dangerous permissions granted
            if (app.dangerousGranted.isNotEmpty) ...[
              _sectionTitle(
                'Sensitive Permissions Granted (${app.dangerousGranted.length})',
                Icons.lock_open_rounded,
                AppTheme.textSecondary,
              ),
              const SizedBox(height: 8),
              CyberCard(
                child: Column(
                  children: app.dangerousGranted
                      .map(
                        (p) => Padding(
                          padding: const EdgeInsets.symmetric(vertical: 4),
                          child: Row(
                            children: [
                              const Icon(
                                Icons.lock_open,
                                size: 12,
                                color: AppTheme.textSecondary,
                              ),
                              const SizedBox(width: 8),
                              Expanded(
                                child: Text(
                                  p
                                      .replaceAll('android.permission.', '')
                                      .replaceAll('_', ' '),
                                  style: AppTheme.bodyMedium.copyWith(
                                    color: AppTheme.textSecondary,
                                  ),
                                ),
                              ),
                            ],
                          ),
                        ),
                      )
                      .toList(),
                ),
              ),
              const SizedBox(height: 16),
            ],

            // All permissions declared
            if (app.allPermissions.isNotEmpty) ...[
              _sectionTitle(
                'All Declared Permissions (${app.allPermissions.length})',
                Icons.list_alt_rounded,
                AppTheme.textSecondary,
              ),
              const SizedBox(height: 8),
              CyberCard(
                child: Column(
                  children: app.allPermissions
                      .map(
                        (p) => Padding(
                          padding: const EdgeInsets.symmetric(vertical: 3),
                          child: Row(
                            children: [
                              Icon(
                                Icons.fiber_manual_record,
                                size: 6,
                                color: app.dangerousGranted.contains(p)
                                    ? AppTheme.textSecondary
                                    : AppTheme.textMuted,
                              ),
                              const SizedBox(width: 8),
                              Expanded(
                                child: Text(
                                  p
                                      .replaceAll('android.permission.', '')
                                      .replaceAll('_', ' '),
                                  style: AppTheme.bodyMedium.copyWith(
                                    color: app.dangerousGranted.contains(p)
                                        ? AppTheme.textSecondary
                                        : AppTheme.textMuted,
                                    fontSize: 11,
                                  ),
                                ),
                              ),
                            ],
                          ),
                        ),
                      )
                      .toList(),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _sectionTitle(String title, IconData icon, Color color) => Row(
    children: [
      Icon(icon, size: 14, color: color),
      const SizedBox(width: 6),
      Text(
        title,
        style: AppTheme.labelSmall.copyWith(
          color: color,
          letterSpacing: 1,
          fontWeight: FontWeight.w700,
        ),
      ),
    ],
  );

  Widget _infoRow(String label, String value) => Padding(
    padding: const EdgeInsets.symmetric(vertical: 5),
    child: Row(
      children: [
        SizedBox(
          width: 120,
          child: Text(
            label,
            style: AppTheme.bodyMedium.copyWith(color: AppTheme.textMuted),
          ),
        ),
        Expanded(
          child: Text(
            value,
            style: AppTheme.bodyMedium,
            overflow: TextOverflow.ellipsis,
          ),
        ),
      ],
    ),
  );

  String _sourceLabel(String src) => switch (src) {
    'play_store' => '✓ Google Play Store',
    'sideloaded' => 'Sideloaded (APK)',
    _ => src.startsWith('other:') ? src.substring(6) : src,
  };
}
