import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:rat3/core/theme/app_theme.dart';
import 'package:rat3/core/utils/app_utils.dart';
import 'package:rat3/data/models/app_models.dart';
import 'package:rat3/data/services/app_controller.dart';
import 'package:rat3/widgets/common_widgets.dart';
import 'package:rat3/widgets/risk_ball.dart';
import 'package:rat3/core/constants/app_constants.dart';

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
            Text('RAT-PREVENTION', style: AppTheme.headlineLarge.copyWith(
              color: AppTheme.neonGreen,
              fontSize: 20,
            )),
            Text('POST-INSTALLATION MONITOR', style: AppTheme.labelSmall),
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
                      color: score.score.riskColor.withOpacity(0.1),
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
        ],
      ),
    );
  }

  Widget _buildStatusCards(RiskScore score, AppController ctrl) {
    return Row(
      children: [
        Expanded(
          child: CyberCard(
            borderColor: AppTheme.neonGreen.withOpacity(0.3),
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
            borderColor: AppTheme.neonCyan.withOpacity(0.3),
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
            borderColor: AppTheme.neonBlue.withOpacity(0.3),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('CONNECTIONS', style: AppTheme.labelSmall),
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

  Widget _buildContributionBreakdown(RiskScore score) {
    return CyberCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const SectionHeader(title: 'Risk Breakdown'),
          const SizedBox(height: 16),
          _buildContribRow('Runtime Behavior', score.runtimeContribution, AppTheme.neonCyan),
          const SizedBox(height: 10),
          _buildContribRow('Network Traffic', score.networkContribution, AppTheme.neonOrange),
          const SizedBox(height: 10),
          _buildContribRow('Permission Abuse', score.permissionContribution, AppTheme.neonRed),
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
        ...recent.map((a) => Padding(
              padding: const EdgeInsets.only(bottom: 8),
              child: CyberCard(
                borderColor: _severityColor(a.severity).withOpacity(0.3),
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
            )),
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