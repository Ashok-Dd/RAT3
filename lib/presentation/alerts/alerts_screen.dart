import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:rat3/core/constants/app_constants.dart';
import 'package:rat3/core/theme/app_theme.dart';
import 'package:rat3/core/utils/app_utils.dart';
import 'package:rat3/data/models/app_models.dart';
import 'package:rat3/data/services/app_controller.dart';
import 'package:rat3/widgets/common_widgets.dart';

class AlertsScreen extends StatefulWidget {
  const AlertsScreen({super.key});

  @override
  State<AlertsScreen> createState() => _AlertsScreenState();
}

class _AlertsScreenState extends State<AlertsScreen> {
  AlertSeverity? _filterSeverity;

  @override
  Widget build(BuildContext context) {
    final ctrl = context.watch<AppController>();
    final allAlerts = ctrl.alerts;
    final filtered = _filterSeverity == null
        ? allAlerts
        : allAlerts.where((a) => a.severity == _filterSeverity).toList();

    return Scaffold(
      backgroundColor: AppTheme.backgroundPrimary,
      body: Column(
        children: [
          _buildFilterBar(),
          Expanded(
            child: filtered.isEmpty
                ? _buildEmpty()
                : ListView.builder(
                    padding: const EdgeInsets.fromLTRB(16, 8, 16, 100),
                    itemCount: filtered.length,
                    itemBuilder: (_, i) => _AlertCard(alert: filtered[i]),
                  ),
          ),
        ],
      ),
      floatingActionButton: allAlerts.isNotEmpty
          ? FloatingActionButton.small(
              heroTag: 'clear_fab',
              onPressed: () => _confirmClear(context, ctrl),
              backgroundColor: AppTheme.backgroundElevated,
              child: const Icon(
                Icons.delete_sweep_outlined,
                color: AppTheme.neonRed,
                size: 20,
              ),
            )
          : null,
    );
  }

  Widget _buildFilterBar() {
    return SingleChildScrollView(
      scrollDirection: Axis.horizontal,
      padding: const EdgeInsets.fromLTRB(16, 12, 16, 8),
      child: Row(
        children: [
          _FilterChip(
            label: 'ALL',
            isSelected: _filterSeverity == null,
            color: AppTheme.neonGreen,
            onTap: () => setState(() => _filterSeverity = null),
          ),
          const SizedBox(width: 8),
          ...AlertSeverity.values.map(
            (s) => Padding(
              padding: const EdgeInsets.only(right: 8),
              child: _FilterChip(
                label: s.label,
                isSelected: _filterSeverity == s,
                color: _colorForSeverity(s),
                onTap: () => setState(() => _filterSeverity = s),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildEmpty() {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(Icons.shield_outlined, size: 48, color: AppTheme.neonGreen),
          const SizedBox(height: 16),
          Text(
            _filterSeverity == null
                ? 'No alerts detected'
                : 'No ${_filterSeverity!.label} alerts',
            style: AppTheme.bodyMedium,
          ),
          const SizedBox(height: 8),
          Text('System is operating normally', style: AppTheme.labelSmall),
        ],
      ),
    );
  }

  Future<void> _confirmClear(BuildContext ctx, AppController ctrl) async {
    final confirmed = await showDialog<bool>(
      context: ctx,
      builder: (_) => AlertDialog(
        backgroundColor: AppTheme.backgroundCard,
        title: Text('Clear All Alerts', style: AppTheme.headlineMedium),
        content: Text(
          'This will remove all stored alerts. Continue?',
          style: AppTheme.bodyMedium,
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: Text(
              'Cancel',
              style: AppTheme.bodyMedium.copyWith(
                color: AppTheme.textSecondary,
              ),
            ),
          ),
          TextButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: Text(
              'Clear',
              style: AppTheme.bodyMedium.copyWith(color: AppTheme.neonRed),
            ),
          ),
        ],
      ),
    );
    if (confirmed == true) await ctrl.alertEngine.clearAlerts();
  }

  Color _colorForSeverity(AlertSeverity s) {
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

class _FilterChip extends StatelessWidget {
  final String label;
  final bool isSelected;
  final Color color;
  final VoidCallback onTap;

  const _FilterChip({
    required this.label,
    required this.isSelected,
    required this.color,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 150),
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
        decoration: BoxDecoration(
          color: isSelected
              ? color.withValues(alpha: 0.2)
              : AppTheme.backgroundCard,
          borderRadius: BorderRadius.circular(4),
          border: Border.all(
            color: isSelected ? color : AppTheme.borderColor,
            width: 1,
          ),
        ),
        child: Text(
          label,
          style: AppTheme.labelSmall.copyWith(
            color: isSelected ? color : AppTheme.textMuted,
            fontWeight: isSelected ? FontWeight.w700 : FontWeight.w400,
          ),
        ),
      ),
    );
  }
}

class _AlertCard extends StatefulWidget {
  final AlertEvent alert;

  const _AlertCard({required this.alert});

  @override
  State<_AlertCard> createState() => _AlertCardState();
}

class _AlertCardState extends State<_AlertCard> {
  bool _expanded = false;

  Color get _color {
    switch (widget.alert.severity) {
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

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: CyberCard(
        borderColor: _color.withValues(alpha: 0.3),
        onTap: () => setState(() => _expanded = !_expanded),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                SeverityBadge(severity: widget.alert.severity),
                const SizedBox(width: 10),
                Expanded(
                  child: Text(widget.alert.title, style: AppTheme.bodyLarge),
                ),
                Icon(
                  _expanded ? Icons.expand_less : Icons.expand_more,
                  color: AppTheme.textMuted,
                  size: 18,
                ),
              ],
            ),
            const SizedBox(height: 6),
            Row(
              children: [
                Text(
                  widget.alert.source.toUpperCase(),
                  style: AppTheme.labelSmall.copyWith(color: _color),
                ),
                const Spacer(),
                Text(
                  AppFormatter.formatTimeAgo(widget.alert.timestamp),
                  style: AppTheme.labelSmall,
                ),
              ],
            ),
            if (_expanded) ...[
              const SizedBox(height: 12),
              const NeonDivider(),
              const SizedBox(height: 12),
              Text(
                widget.alert.userFriendlyMessage,
                style: AppTheme.bodyMedium.copyWith(
                  color: AppTheme.textPrimary,
                  height: 1.5,
                ),
              ),
              const SizedBox(height: 8),
              Text(
                AppFormatter.formatDateTime(widget.alert.timestamp),
                style: AppTheme.labelSmall,
              ),
            ],
          ],
        ),
      ),
    );
  }
}
