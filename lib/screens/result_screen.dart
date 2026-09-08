import 'package:flutter/material.dart';

import '../models/scan_result.dart';
import '../services/apk_scanner_service.dart';
import '../theme/app_theme.dart';
import '../widgets/info_card.dart';
import '../widgets/layer_findings_card.dart';
import '../widgets/section_label.dart';

/// Shows the verdict, overall risk score, per-layer findings and the install action.
class ResultScreen extends StatelessWidget {
  const ResultScreen({super.key, required this.result});

  final ScanResult result;

  static const _layerMeta = [
    (
      title: 'Layer 1: App Safety Analysis',
      icon: Icons.rule,
      color: AppColors.primary,
    ),
    (
      title: 'Layer 2: Permission Mismatch',
      icon: Icons.compare_arrows,
      color: AppColors.accentYellow,
    ),
    (
      title: 'Layer 3: Malware Signatures',
      icon: Icons.fingerprint,
      color: AppColors.accentOrange,
    ),
    (
      title: 'Layer 4: Heuristic Risk Model',
      icon: Icons.psychology,
      color: AppColors.accentTeal,
    ),
  ];

  bool get _isSafe => result.verdict == 'SAFE';

  Color get _verdictColor => switch (result.verdict) {
    'SAFE' => AppColors.safe,
    'SUSPICIOUS' => AppColors.suspicious,
    _ => AppColors.danger,
  };

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Scan Result')),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(20),
        child: Column(
          children: [
            _verdictCard(),
            const SizedBox(height: 20),
            _riskScoreCard(),
            const SizedBox(height: 20),
            _layerResults(),
            const SizedBox(height: 24),
            _actions(context),
            const SizedBox(height: 20),
          ],
        ),
      ),
    );
  }

  Widget _verdictCard() {
    return InfoCard(
      glow: true,
      borderColor: _verdictColor.withValues(alpha: 0.5),
      padding: const EdgeInsets.all(24),
      child: Column(
        children: [
          Icon(
            _isSafe ? Icons.verified_user : Icons.gpp_bad,
            size: 64,
            color: _verdictColor,
          ),
          const SizedBox(height: 12),
          Text(
            result.verdict,
            style: TextStyle(
              fontSize: 32,
              fontWeight: FontWeight.bold,
              color: _verdictColor,
              letterSpacing: 3,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            result.summary,
            textAlign: TextAlign.center,
            style: const TextStyle(color: AppColors.textMuted, fontSize: 13),
          ),
        ],
      ),
    );
  }

  Widget _riskScoreCard() {
    final score = result.overallRiskScore;
    final color = AppColors.forScore(score);
    return InfoCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              const SectionLabel('OVERALL RISK SCORE'),
              Text(
                '$score / 100',
                style: TextStyle(
                  color: color,
                  fontWeight: FontWeight.bold,
                  fontSize: 16,
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          ClipRRect(
            borderRadius: BorderRadius.circular(4),
            child: LinearProgressIndicator(
              value: score / 100,
              backgroundColor: AppColors.background,
              valueColor: AlwaysStoppedAnimation<Color>(color),
              minHeight: 8,
            ),
          ),
        ],
      ),
    );
  }

  Widget _layerResults() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const SectionLabel('LAYER ANALYSIS'),
        const SizedBox(height: 12),
        for (var i = 0; i < _layerMeta.length; i++)
          LayerFindingsCard(
            title: _layerMeta[i].title,
            icon: _layerMeta[i].icon,
            accent: _layerMeta[i].color,
            result: result.layers[i],
          ),
      ],
    );
  }

  Widget _actions(BuildContext context) {
    if (_isSafe) {
      return Column(
        children: [
          _primaryButton(
            label: 'INSTALL APK',
            icon: Icons.install_mobile,
            color: AppColors.accentTeal,
            onPressed: () => _confirmAndInstall(context),
          ),
          const SizedBox(height: 12),
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text(
              'Cancel',
              style: TextStyle(color: AppColors.textMuted),
            ),
          ),
        ],
      );
    }

    return Column(
      children: [
        Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: AppColors.danger.withValues(alpha: 0.1),
            borderRadius: BorderRadius.circular(10),
            border: Border.all(color: AppColors.danger.withValues(alpha: 0.4)),
          ),
          child: const Row(
            children: [
              Icon(Icons.warning_amber, color: AppColors.danger, size: 20),
              SizedBox(width: 10),
              Expanded(
                child: Text(
                  'This APK has been flagged as potentially dangerous. Installation is not recommended.',
                  style: TextStyle(color: AppColors.dangerText, fontSize: 12),
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 16),
        SizedBox(
          width: double.infinity,
          height: 52,
          child: OutlinedButton.icon(
            onPressed: () => _confirmRiskyInstall(context),
            icon: const Icon(Icons.warning_amber, color: AppColors.danger),
            label: const Text(
              'INSTALL ANYWAY (RISK)',
              style: TextStyle(
                color: AppColors.danger,
                fontWeight: FontWeight.bold,
                letterSpacing: 1.2,
              ),
            ),
            style: OutlinedButton.styleFrom(
              side: const BorderSide(color: AppColors.danger),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(10),
              ),
            ),
          ),
        ),
        const SizedBox(height: 12),
        _primaryButton(
          label: 'CANCEL INSTALLATION',
          icon: Icons.cancel,
          color: AppColors.accentTeal,
          onPressed: () => Navigator.of(context).pop(),
        ),
      ],
    );
  }

  Widget _primaryButton({
    required String label,
    required IconData icon,
    required Color color,
    required VoidCallback onPressed,
  }) {
    return SizedBox(
      width: double.infinity,
      height: 52,
      child: ElevatedButton.icon(
        onPressed: onPressed,
        icon: Icon(icon),
        label: Text(
          label,
          style: const TextStyle(
            fontWeight: FontWeight.bold,
            letterSpacing: 1.2,
          ),
        ),
        style: ElevatedButton.styleFrom(
          backgroundColor: color,
          foregroundColor: AppColors.background,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(10),
          ),
        ),
      ),
    );
  }

  Future<void> _confirmAndInstall(BuildContext context) async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: AppColors.surface,
        title: const Text(
          'Install this APK?',
          style: TextStyle(color: AppColors.textPrimary),
        ),
        content: const Text(
          'RAT3 found no significant threats, but this is a heuristic scan — it cannot '
          'guarantee the app is safe. Continue to the system installer?',
          style: TextStyle(color: AppColors.textMuted),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text(
              'Cancel',
              style: TextStyle(color: AppColors.textMuted),
            ),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(ctx, true),
            style: ElevatedButton.styleFrom(
              backgroundColor: AppColors.accentTeal,
            ),
            child: const Text('Install'),
          ),
        ],
      ),
    );
    if (ok == true && context.mounted) await _install(context);
  }

  Future<void> _confirmRiskyInstall(BuildContext context) async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: AppColors.surface,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        title: const Row(
          children: [
            Icon(Icons.gpp_bad, color: AppColors.danger),
            SizedBox(width: 8),
            Text(
              'Security Warning',
              style: TextStyle(color: AppColors.textPrimary, fontSize: 18),
            ),
          ],
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'RAT3 detected threats in this APK:',
              style: TextStyle(color: AppColors.textMuted),
            ),
            const SizedBox(height: 12),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: AppColors.danger.withValues(alpha: 0.08),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(
                  color: AppColors.danger.withValues(alpha: 0.3),
                ),
              ),
              child: Text(
                result.summary,
                style: const TextStyle(
                  color: AppColors.dangerText,
                  fontSize: 12,
                ),
              ),
            ),
            const SizedBox(height: 16),
            const Text(
              'By proceeding you accept all responsibility for any damage caused.',
              style: TextStyle(color: AppColors.textMuted, fontSize: 12),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text(
              'Cancel',
              style: TextStyle(color: AppColors.accentTeal),
            ),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(ctx, true),
            style: ElevatedButton.styleFrom(backgroundColor: AppColors.danger),
            child: const Text('Install Anyway'),
          ),
        ],
      ),
    );
    if (ok == true && context.mounted) await _install(context);
  }

  Future<void> _install(BuildContext context) async {
    final messenger = ScaffoldMessenger.of(context);
    try {
      await ApkScannerService().installApk(result.apkPath);
    } on InstallPermissionRequiredException catch (e) {
      messenger.showSnackBar(SnackBar(content: Text(e.message)));
    } catch (e) {
      messenger.showSnackBar(SnackBar(content: Text('Install failed: $e')));
    }
  }
}
