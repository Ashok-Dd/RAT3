import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:rat3/core/theme/app_theme.dart';
import 'package:rat3/data/services/app_controller.dart';
import 'package:rat3/presentation/onboarding/onboarding_screen.dart';
import 'package:rat3/widgets/common_widgets.dart';

class SettingsScreen extends StatelessWidget {
  const SettingsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final ctrl = context.watch<AppController>();

    return Scaffold(
      backgroundColor: AppTheme.backgroundPrimary,
      body: ListView(
        padding: const EdgeInsets.fromLTRB(16, 16, 16, 100),
        children: [
          const SectionHeader(title: 'Monitoring'),
          const SizedBox(height: 12),
          CyberCard(
            child: Column(
              children: [
                _ToggleTile(
                  label: 'Enable Monitoring',
                  sublabel: 'Continuously analyze runtime behavior',
                  value: ctrl.isMonitoringEnabled,
                  onChanged: ctrl.setMonitoringEnabled,
                  activeColor: AppTheme.neonGreen,
                ),
                const NeonDivider(),
                _ToggleTile(
                  label: 'Push Notifications',
                  sublabel: 'Receive alerts for suspicious activity',
                  value: ctrl.notificationsEnabled,
                  onChanged: ctrl.setNotificationsEnabled,
                  activeColor: AppTheme.neonCyan,
                ),
              ],
            ),
          ),
          const SizedBox(height: 24),
          const SectionHeader(title: 'Permissions'),
          const SizedBox(height: 12),
          CyberCard(
            child: _ActionTile(
              label: 'Fix permissions',
              sublabel:
                  'Re-run the setup wizard for usage access, notifications…',
              icon: Icons.tune,
              color: AppTheme.neonCyan,
              onTap: () => Navigator.of(context).push(
                MaterialPageRoute<void>(
                  builder: (_) => const OnboardingScreen(),
                ),
              ),
            ),
          ),
          const SizedBox(height: 24),
          const SectionHeader(title: 'Risk Score'),
          const SizedBox(height: 12),
          CyberCard(
            borderColor: AppTheme.neonRed.withValues(alpha: 0.2),
            child: _ActionTile(
              label: 'Reset Risk Score',
              sublabel: 'Clear all data and start fresh',
              icon: Icons.restart_alt_rounded,
              color: AppTheme.neonRed,
              onTap: () => _confirmReset(context, ctrl),
            ),
          ),
          const SizedBox(height: 24),
          const SectionHeader(title: 'About'),
          const SizedBox(height: 12),
          CyberCard(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                _InfoRow(label: 'App', value: 'RAT3'),
                const NeonDivider(),
                _InfoRow(label: 'Version', value: ctrl.appVersion),
                const NeonDivider(),
                _InfoRow(label: 'Platform', value: 'Flutter / Android'),
                const NeonDivider(),
                _InfoRow(
                  label: 'Build',
                  value: ctrl.isReleaseBuild ? 'Release build' : 'Debug build',
                ),
              ],
            ),
          ),
          const SizedBox(height: 24),
          Center(
            child: Text(
              '🛡 Protecting your device 24/7',
              style: AppTheme.labelSmall.copyWith(color: AppTheme.neonGreen),
            ),
          ),
        ],
      ),
    );
  }

  Future<void> _confirmReset(BuildContext context, AppController ctrl) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (_) => AlertDialog(
        backgroundColor: AppTheme.backgroundCard,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(8),
          side: const BorderSide(color: AppTheme.neonRed, width: 1),
        ),
        title: Text('Reset Risk Score', style: AppTheme.headlineMedium),
        content: Text(
          'This will clear all alerts, connections, and the current risk score. '
          'This action cannot be undone.',
          style: AppTheme.bodyMedium.copyWith(height: 1.5),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: Text(
              'Cancel',
              style: AppTheme.bodyMedium.copyWith(
                color: AppTheme.textSecondary,
              ),
            ),
          ),
          TextButton(
            onPressed: () => Navigator.pop(context, true),
            child: Text(
              'Reset',
              style: AppTheme.bodyMedium.copyWith(color: AppTheme.neonRed),
            ),
          ),
        ],
      ),
    );

    if (confirmed == true) {
      await ctrl.resetRiskScore();
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Risk score has been reset.')),
        );
      }
    }
  }
}

class _ToggleTile extends StatelessWidget {
  final String label;
  final String sublabel;
  final bool value;
  final ValueChanged<bool> onChanged;
  final Color activeColor;

  const _ToggleTile({
    required this.label,
    required this.sublabel,
    required this.value,
    required this.onChanged,
    required this.activeColor,
  });

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(label, style: AppTheme.bodyLarge),
                Text(sublabel, style: AppTheme.bodyMedium),
              ],
            ),
          ),
          Switch(
            value: value,
            onChanged: onChanged,
            activeThumbColor: activeColor,
          ),
        ],
      ),
    );
  }
}

class _ActionTile extends StatelessWidget {
  final String label;
  final String sublabel;
  final IconData icon;
  final Color color;
  final VoidCallback onTap;

  const _ActionTile({
    required this.label,
    required this.sublabel,
    required this.icon,
    required this.color,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: Row(
        children: [
          Icon(icon, color: color, size: 20),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(label, style: AppTheme.bodyLarge.copyWith(color: color)),
                Text(sublabel, style: AppTheme.bodyMedium),
              ],
            ),
          ),
          Icon(Icons.chevron_right, color: AppTheme.textMuted, size: 18),
        ],
      ),
    );
  }
}

class _InfoRow extends StatelessWidget {
  final String label;
  final String value;

  const _InfoRow({required this.label, required this.value});

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 10),
      child: Row(
        children: [
          Text(label, style: AppTheme.bodyMedium),
          const Spacer(),
          Text(
            value,
            style: AppTheme.bodyLarge.copyWith(color: AppTheme.neonGreen),
          ),
        ],
      ),
    );
  }
}
