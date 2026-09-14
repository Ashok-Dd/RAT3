import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:rat3/core/constants/app_constants.dart';
import 'package:rat3/core/theme/app_theme.dart';
import 'package:rat3/core/utils/app_utils.dart';
import 'package:rat3/data/models/app_models.dart';
import 'package:rat3/data/services/app_controller.dart';
import 'package:rat3/widgets/common_widgets.dart';
import 'package:rat3/widgets/risk_ball.dart';

class DashboardScreen extends StatelessWidget {
  const DashboardScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final ctrl = context.watch<AppController>();
    final score = ctrl.riskScore;
    final alerts = ctrl.alerts;

    return Scaffold(
      backgroundColor: AppTheme.backgroundPrimary,
      body: SingleChildScrollView(
        padding: const EdgeInsets.fromLTRB(16, 16, 16, 100),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _buildHeader(ctrl),
            const SizedBox(height: 24),
            _buildRiskBallSection(score, ctrl),
            const SizedBox(height: 24),
            _buildStatusCards(score, ctrl),
            const SizedBox(height: 24),
            _buildContributionBreakdown(score),
            const SizedBox(height: 24),
            _buildRecentAlerts(alerts, context),
          ],
        ),
      ),
    );
  }

  Widget _buildHeader(AppController ctrl) {
    return Row(
      children: [
        Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'DEVICE MONITOR',
              style: AppTheme.headlineLarge.copyWith(
                color: AppTheme.neonGreen,
                fontSize: 20,
              ),
            ),
            Text('LIVE RAT / SPYWARE WATCH', style: AppTheme.labelSmall),
          ],
        ),
        const Spacer(),
        if (ctrl.isMonitoringEnabled) const ScanPulse(),
        const SizedBox(width: 8),
        Text(
          ctrl.isMonitoringEnabled ? 'ACTIVE' : 'PAUSED',
          style: AppTheme.labelSmall.copyWith(
            color: ctrl.isMonitoringEnabled
                ? AppTheme.neonGreen
                : AppTheme.textMuted,
          ),
        ),
      ],
    );
  }

  Widget _buildRiskBallSection(RiskScore score, AppController ctrl) {
    return Center(
      child: Column(
        children: [
          Stack(
            alignment: Alignment.center,
            children: [
              // Outer glow rings
              Container(
                width: 240,
                height: 240,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  boxShadow: [
                    BoxShadow(
                      color: score.score.riskColor.withValues(alpha: 0.1),
                      blurRadius: 40,
                      spreadRadius: 10,
                    ),
                  ],
                ),
              ),
              RiskBall(score: score.score, size: 200),
            ],
          ),
          const SizedBox(height: 16),
          RiskLevelBadge(level: score.level, large: true),
          const SizedBox(height: 8),
          Text(
            'Last scan: ${ctrl.lastScanTime != null ? AppFormatter.formatTimeAgo(ctrl.lastScanTime!) : 'Never'}',
            style: AppTheme.bodyMedium,
          ),
          const SizedBox(height: 12),
          _buildScanSummary(ctrl.alerts, score.level),
        ],
      ),
    );
  }

  // Honest, calm scan summary: what RAT3 actually found, in plain findings
  // counts, plus an explicit statement of scope — never "no RAT found",
  // only "no strong indicators within what RAT3 can inspect".
  Widget _buildScanSummary(List<AlertEvent> alerts, RiskLevel level) {
    final critical = alerts
        .where((a) => a.severity == AlertSeverity.critical)
        .length;
    final high = alerts.where((a) => a.severity == AlertSeverity.high).length;
    final medium = alerts
        .where((a) => a.severity == AlertSeverity.medium)
        .length;
    final low = alerts.where((a) => a.severity == AlertSeverity.low).length;

    final headline = switch (level) {
      RiskLevel.safe =>
        'No strong indicators of RAT malware were found within the areas RAT3 can inspect.',
      RiskLevel.monitor =>
        'A few minor signals are being watched — nothing conclusive yet.',
      RiskLevel.suspicious =>
        'Some indicators are worth reviewing — see Alerts for details.',
      RiskLevel.highRisk =>
        'Multiple correlated indicators were found — review Alerts soon.',
      RiskLevel.critical =>
        'Strong, correlated indicators of compromise were found — review Alerts now.',
    };

    return Column(
      children: [
        Text(
          headline,
          style: AppTheme.bodyMedium.copyWith(color: AppTheme.textMuted),
          textAlign: TextAlign.center,
        ),
        const SizedBox(height: 10),
        Wrap(
          alignment: WrapAlignment.center,
          spacing: 12,
          children: [
            _findingChip('$critical', 'CRITICAL', AppTheme.statusCritical),
            _findingChip('$high', 'HIGH', AppTheme.statusHighRisk),
            _findingChip('$medium', 'MEDIUM', AppTheme.statusSuspicious),
            _findingChip('$low', 'INFO', AppTheme.textMuted),
          ],
        ),
      ],
    );
  }

  Widget _findingChip(String count, String label, Color color) => Row(
    mainAxisSize: MainAxisSize.min,
    children: [
      Text(
        count,
        style: AppTheme.bodyMedium.copyWith(
          color: color,
          fontWeight: FontWeight.w800,
        ),
      ),
      const SizedBox(width: 3),
      Text(
        label,
        style: AppTheme.labelSmall.copyWith(color: color, fontSize: 9),
      ),
    ],
  );

  Widget _buildStatusCards(RiskScore score, AppController ctrl) {
    return Row(
      children: [
        Expanded(
          child: CyberCard(
            borderColor: AppTheme.neonGreen.withValues(alpha: 0.3),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('MONITORING', style: AppTheme.labelSmall),
                const SizedBox(height: 6),
                Text(
                  ctrl.isMonitoringEnabled ? 'ON' : 'OFF',
                  style: AppTheme.headlineMedium.copyWith(
                    color: ctrl.isMonitoringEnabled
                        ? AppTheme.neonGreen
                        : AppTheme.textMuted,
                  ),
                ),
              ],
            ),
          ),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: CyberCard(
            borderColor: AppTheme.neonCyan.withValues(alpha: 0.3),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('ALERTS', style: AppTheme.labelSmall),
                const SizedBox(height: 6),
                Text(
                  '${ctrl.alerts.length}',
                  style: AppTheme.headlineMedium.copyWith(
                    color: ctrl.alertEngine.criticalCount > 0
                        ? AppTheme.neonRed
                        : AppTheme.neonCyan,
                  ),
                ),
              ],
            ),
          ),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: CyberCard(
            borderColor: AppTheme.neonBlue.withValues(alpha: 0.3),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('LINKS', style: AppTheme.labelSmall, maxLines: 1),
                const SizedBox(height: 6),
                Text(
                  '${ctrl.connections.length}',
                  style: AppTheme.headlineMedium.copyWith(
                    color: AppTheme.neonBlue,
                  ),
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }

  // The six weighted categories behind the overall score, in descending
  // weight order (Sensor/Network 25%, App 20%, System 15%, Permission 10%,
  // Aggregated 5% — see docs/post-installation/07-risk-scoring-engine.md).
  // All six must be shown here, not a subset — each bar is 5-25% of the
  // score, so omitting any of them hides that much of "why" from the user.
  Widget _buildContributionBreakdown(RiskScore score) {
    return CyberCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const SectionHeader(title: 'Risk Breakdown'),
          const SizedBox(height: 16),
          _buildContribRow(
            'Sensor Behavior',
            score.sensorContribution,
            AppTheme.neonGreen,
          ),
          const SizedBox(height: 10),
          _buildContribRow(
            'Network & Resource',
            score.networkContribution,
            AppTheme.neonOrange,
          ),
          const SizedBox(height: 10),
          _buildContribRow(
            'App Behavior',
            score.appContribution,
            AppTheme.neonYellow,
          ),
          const SizedBox(height: 10),
          _buildContribRow(
            'System Security',
            score.runtimeContribution,
            AppTheme.neonCyan,
          ),
          const SizedBox(height: 10),
          _buildContribRow(
            'Permission Behavior',
            score.permissionContribution,
            AppTheme.neonRed,
          ),
          const SizedBox(height: 10),
          _buildContribRow(
            'Aggregated Correlations',
            score.aggregatedContribution,
            AppTheme.neonBlue,
          ),
        ],
      ),
    );
  }

  Widget _buildContribRow(String label, double value, Color color) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Text(label, style: AppTheme.bodyMedium),
            const Spacer(),
            Text(
              '${value.toStringAsFixed(1)}%',
              style: AppTheme.bodyMedium.copyWith(color: color),
            ),
          ],
        ),
        const SizedBox(height: 4),
        ClipRRect(
          borderRadius: BorderRadius.circular(2),
          child: LinearProgressIndicator(
            value: (value / 100).clamp(0.0, 1.0),
            backgroundColor: AppTheme.borderColor,
            valueColor: AlwaysStoppedAnimation(color),
            minHeight: 4,
          ),
        ),
      ],
    );
  }

  Widget _buildRecentAlerts(List<AlertEvent> alerts, BuildContext context) {
    final recent = alerts.take(3).toList();
    if (recent.isEmpty) {
      return CyberCard(
        child: Column(
          children: [
            const SectionHeader(title: 'Recent Alerts'),
            const SizedBox(height: 16),
            Text('No alerts detected.', style: AppTheme.bodyMedium),
          ],
        ),
      );
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const SectionHeader(title: 'Recent Alerts'),
        const SizedBox(height: 12),
        ...recent.map(
          (a) => Padding(
            padding: const EdgeInsets.only(bottom: 8),
            child: CyberCard(
              borderColor: _severityColor(a.severity).withValues(alpha: 0.3),
              child: Row(
                children: [
                  SeverityBadge(severity: a.severity),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(a.title, style: AppTheme.bodyLarge),
                        Text(
                          AppFormatter.formatTimeAgo(a.timestamp),
                          style: AppTheme.labelSmall,
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ],
    );
  }

  Color _severityColor(AlertSeverity s) {
    switch (s) {
      case AlertSeverity.low:
        return AppTheme.neonCyan;
      case AlertSeverity.medium:
        return AppTheme.neonYellow;
      case AlertSeverity.high:
        return AppTheme.neonOrange;
      case AlertSeverity.critical:
        return AppTheme.neonRed;
    }
  }
}
