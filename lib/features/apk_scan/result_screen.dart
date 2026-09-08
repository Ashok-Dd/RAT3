import 'package:flutter/material.dart';

import '../../core/theme/app_theme.dart';
import '../../widgets/common_widgets.dart';
import '../../widgets/risk_ball.dart';
import 'models/scan_result.dart';
import 'services/apk_scanner_service.dart';

/// Shows the pre-install APK scan verdict, per-layer findings and the install action.
class ApkResultScreen extends StatelessWidget {
  const ApkResultScreen({super.key, required this.result});

  final ScanResult result;

  static const _layerMeta = [
    (title: 'App Safety Analysis', icon: Icons.rule),
    (title: 'Permission Mismatch', icon: Icons.compare_arrows),
    (title: 'Malware Signatures', icon: Icons.fingerprint),
    (title: 'ML Malware Classifier', icon: Icons.psychology),
  ];

  bool get _isSafe => result.verdict == 'SAFE';

  Color get _verdictColor => switch (result.verdict) {
    'SAFE' => AppTheme.colorSafe,
    'SUSPICIOUS' => AppTheme.colorSuspicious,
    _ => AppTheme.colorDangerous,
  };

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('SCAN RESULT')),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.fromLTRB(16, 16, 16, 32),
          child: Column(
            children: [
              _verdictCard(),
              const SizedBox(height: 20),
              _scoreCard(),
              const SizedBox(height: 20),
              _layers(),
              const SizedBox(height: 24),
              _actions(context),
            ],
          ),
        ),
      ),
    );
  }

  Widget _verdictCard() {
    return CyberCard(
      borderColor: _verdictColor.withValues(alpha: 0.5),
      padding: const EdgeInsets.all(24),
      child: Column(
        children: [
          Icon(_isSafe ? Icons.verified_user : Icons.gpp_bad, size: 56, color: _verdictColor),
          const SizedBox(height: 12),
          Text(
            result.verdict,
            style: AppTheme.headlineLarge.copyWith(
              color: _verdictColor,
              fontSize: 30,
              letterSpacing: 3,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            result.summary,
            textAlign: TextAlign.center,
            style: AppTheme.bodyMedium,
          ),
        ],
      ),
    );
  }

  Widget _scoreCard() {
    return CyberCard(
      child: Column(
        children: [
          const Align(
            alignment: Alignment.centerLeft,
            child: SectionHeader(title: 'Overall Risk'),
          ),
          const SizedBox(height: 16),
          RiskBall(score: result.overallRiskScore, size: 150),
        ],
      ),
    );
  }

  Widget _layers() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const SectionHeader(title: 'Layer Analysis'),
        const SizedBox(height: 12),
        for (var i = 0; i < _layerMeta.length; i++)
          _LayerTile(
            title: 'Layer ${i + 1}: ${_layerMeta[i].title}',
            icon: _layerMeta[i].icon,
            layer: result.layers[i],
          ),
      ],
    );
  }

  Widget _actions(BuildContext context) {
    if (_isSafe) {
      return Column(
        children: [
          SizedBox(
            width: double.infinity,
            child: ElevatedButton.icon(
              onPressed: () => _confirmInstall(context),
              icon: const Icon(Icons.install_mobile),
              label: const Text('INSTALL APK'),
            ),
          ),
          const SizedBox(height: 8),
          TextButton(
            onPressed: () => Navigator.of(context).maybePop(),
            child: Text('Cancel', style: AppTheme.bodyMedium),
          ),
        ],
      );
    }
    return Column(
      children: [
        CyberCard(
          borderColor: AppTheme.neonRed.withValues(alpha: 0.4),
          child: Row(
            children: [
              const Icon(Icons.warning_amber, color: AppTheme.neonRed, size: 20),
              const SizedBox(width: 10),
              Expanded(
                child: Text(
                  'Flagged as potentially dangerous. Installation is not recommended.',
                  style: AppTheme.bodyMedium.copyWith(color: AppTheme.neonRed),
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 12),
        SizedBox(
          width: double.infinity,
          child: OutlinedButton.icon(
            onPressed: () => _confirmRiskyInstall(context),
            icon: const Icon(Icons.warning_amber, color: AppTheme.neonRed),
            label: const Text('INSTALL ANYWAY (RISK)', style: TextStyle(color: AppTheme.neonRed)),
            style: OutlinedButton.styleFrom(side: const BorderSide(color: AppTheme.neonRed)),
          ),
        ),
        const SizedBox(height: 8),
        SizedBox(
          width: double.infinity,
          child: ElevatedButton(
            onPressed: () => Navigator.of(context).maybePop(),
            child: const Text('CANCEL'),
          ),
        ),
      ],
    );
  }

  Future<void> _confirmInstall(BuildContext context) async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: AppTheme.backgroundCard,
        title: const Text('Install this APK?'),
        content: Text(
          'No significant threats were found, but a scan cannot guarantee safety. '
          'Continue to the system installer?',
          style: AppTheme.bodyMedium,
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          ElevatedButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('Install')),
        ],
      ),
    );
    if (ok == true && context.mounted) await _install(context);
  }

  Future<void> _confirmRiskyInstall(BuildContext context) async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: AppTheme.backgroundCard,
        title: const Row(
          children: [
            Icon(Icons.gpp_bad, color: AppTheme.neonRed),
            SizedBox(width: 8),
            Text('Security Warning'),
          ],
        ),
        content: Text(
          '${result.summary}\n\nBy proceeding you accept all responsibility for any damage caused.',
          style: AppTheme.bodyMedium,
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          ElevatedButton(
            onPressed: () => Navigator.pop(ctx, true),
            style: ElevatedButton.styleFrom(backgroundColor: AppTheme.neonRed),
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

class _LayerTile extends StatelessWidget {
  const _LayerTile({required this.title, required this.icon, required this.layer});

  final String title;
  final IconData icon;
  final LayerResult layer;

  @override
  Widget build(BuildContext context) {
    final color = AppTheme.riskColor(layer.riskScore);
    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      decoration: BoxDecoration(
        color: AppTheme.backgroundCard,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: AppTheme.borderColor),
      ),
      child: Theme(
        data: Theme.of(context).copyWith(dividerColor: Colors.transparent),
        child: ExpansionTile(
          tilePadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 2),
          childrenPadding: const EdgeInsets.fromLTRB(14, 0, 14, 14),
          leading: Icon(icon, color: AppTheme.neonCyan, size: 20),
          title: Text(title, style: AppTheme.bodyLarge.copyWith(fontWeight: FontWeight.w600)),
          trailing: Container(
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 3),
            decoration: BoxDecoration(
              color: color.withValues(alpha: 0.15),
              borderRadius: BorderRadius.circular(20),
            ),
            child: Text(
              '${layer.riskScore}',
              style: TextStyle(color: color, fontWeight: FontWeight.bold, fontSize: 13),
            ),
          ),
          children: [
            const NeonDivider(),
            const SizedBox(height: 8),
            if (layer.analysisError)
              _finding(const Finding(message: 'This layer could not complete — findings are partial.', isWarning: true)),
            ...layer.findings.map(_finding),
          ],
        ),
      ),
    );
  }

  Widget _finding(Finding f) => Padding(
    padding: const EdgeInsets.only(bottom: 6),
    child: Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Icon(
          f.isWarning ? Icons.warning_amber : Icons.info_outline,
          size: 14,
          color: f.isWarning ? AppTheme.neonOrange : AppTheme.textMuted,
        ),
        const SizedBox(width: 8),
        Expanded(child: Text(f.message, style: AppTheme.bodyMedium)),
      ],
    ),
  );
}
