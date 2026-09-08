import 'package:flutter/material.dart';

import '../services/apk_scanner_service.dart';
import '../theme/app_theme.dart';
import '../widgets/info_card.dart';
import '../widgets/pulse_dot.dart';
import '../widgets/section_label.dart';
import 'scanning_screen.dart';

/// Landing screen: explains the scanner and lets the user pick an APK.
///
/// "Open with RAT3" while the app is already open is handled centrally in
/// `app.dart` (via [ApkScannerService.onIncomingApk]) — this screen no longer
/// registers its own platform-channel handler.
class HomeScreen extends StatelessWidget {
  const HomeScreen({super.key});

  static const _layers = [
    (
      icon: Icons.rule,
      title: 'Layer 1',
      subtitle: 'App Safety Analysis',
      color: AppColors.primary,
    ),
    (
      icon: Icons.compare_arrows,
      title: 'Layer 2',
      subtitle: 'Permission Mismatch',
      color: AppColors.accentYellow,
    ),
    (
      icon: Icons.fingerprint,
      title: 'Layer 3',
      subtitle: 'Malware Signatures',
      color: AppColors.accentOrange,
    ),
    (
      icon: Icons.psychology,
      title: 'Layer 4',
      subtitle: 'Heuristic Risk Model',
      color: AppColors.accentTeal,
    ),
  ];

  Future<void> _pickAndScan(BuildContext context) async {
    final apkPath = await ApkScannerService().pickApkFile();
    if (apkPath == null || !context.mounted) return;
    await Navigator.of(context).push(
      MaterialPageRoute<void>(builder: (_) => ScanningScreen(apkPath: apkPath)),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Row(
          children: [
            Icon(Icons.security, color: AppColors.primary, size: 24),
            SizedBox(width: 8),
            Text(
              'RAT3',
              style: TextStyle(
                color: AppColors.primary,
                fontWeight: FontWeight.bold,
                letterSpacing: 3,
              ),
            ),
          ],
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.info_outline, color: AppColors.textMuted),
            onPressed: () => _showAbout(context),
          ),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _statusCard(),
            const SizedBox(height: 24),
            _scanCard(context),
            const SizedBox(height: 24),
            const SectionLabel('SECURITY LAYERS'),
            const SizedBox(height: 12),
            _layersGrid(),
            const SizedBox(height: 24),
            _howItWorks(),
          ],
        ),
      ),
    );
  }

  Widget _statusCard() {
    return InfoCard(
      borderColor: AppColors.accentTeal.withValues(alpha: 0.3),
      padding: const EdgeInsets.all(20),
      child: const Row(
        children: [
          PulseDot(),
          SizedBox(width: 12),
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'All security modules active',
                style: TextStyle(
                  color: AppColors.accentTeal,
                  fontWeight: FontWeight.w600,
                ),
              ),
              Text(
                '4 layers ready • Open an APK to scan',
                style: TextStyle(color: AppColors.textMuted, fontSize: 12),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _scanCard(BuildContext context) {
    return InfoCard(
      glow: true,
      borderColor: AppColors.primary.withValues(alpha: 0.2),
      padding: const EdgeInsets.all(32),
      child: Column(
        children: [
          const Icon(
            Icons.find_in_page_outlined,
            size: 64,
            color: AppColors.primary,
          ),
          const SizedBox(height: 16),
          const Text(
            'Scan APK File',
            style: TextStyle(
              fontSize: 22,
              fontWeight: FontWeight.bold,
              color: AppColors.textPrimary,
            ),
          ),
          const SizedBox(height: 8),
          const Text(
            'Analyse an APK with a 4-layer security scan before you install it.',
            textAlign: TextAlign.center,
            style: TextStyle(color: AppColors.textMuted, fontSize: 13),
          ),
          const SizedBox(height: 24),
          SizedBox(
            width: double.infinity,
            height: 52,
            child: ElevatedButton.icon(
              onPressed: () => _pickAndScan(context),
              icon: const Icon(Icons.upload_file),
              label: const Text(
                'SELECT APK FILE',
                style: TextStyle(
                  fontWeight: FontWeight.bold,
                  letterSpacing: 1.5,
                  fontSize: 14,
                ),
              ),
              style: ElevatedButton.styleFrom(
                backgroundColor: AppColors.primary,
                foregroundColor: AppColors.background,
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(10),
                ),
              ),
            ),
          ),
          const SizedBox(height: 16),
          _hint(),
        ],
      ),
    );
  }

  Widget _hint() {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
      decoration: BoxDecoration(
        color: AppColors.background,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: AppColors.border),
      ),
      child: const Row(
        children: [
          Icon(Icons.folder_open, size: 16, color: AppColors.primary),
          SizedBox(width: 10),
          Expanded(
            child: Text(
              'Or tap any APK in your file manager → "Open with RAT3" → the scan starts automatically.',
              style: TextStyle(color: AppColors.textMuted, fontSize: 11),
            ),
          ),
        ],
      ),
    );
  }

  Widget _layersGrid() {
    return GridView.builder(
      shrinkWrap: true,
      physics: const NeverScrollableScrollPhysics(),
      gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount: 2,
        mainAxisSpacing: 12,
        crossAxisSpacing: 12,
        childAspectRatio: 2.2,
      ),
      itemCount: _layers.length,
      itemBuilder: (context, i) {
        final layer = _layers[i];
        return Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: AppColors.surface,
            borderRadius: BorderRadius.circular(10),
            border: Border.all(color: layer.color.withValues(alpha: 0.3)),
          ),
          child: Row(
            children: [
              Icon(layer.icon, color: layer.color, size: 22),
              const SizedBox(width: 8),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Text(
                      layer.title,
                      style: TextStyle(
                        color: layer.color,
                        fontSize: 11,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    Text(
                      layer.subtitle,
                      style: const TextStyle(
                        color: AppColors.textMuted,
                        fontSize: 10,
                      ),
                      overflow: TextOverflow.ellipsis,
                    ),
                  ],
                ),
              ),
            ],
          ),
        );
      },
    );
  }

  Widget _howItWorks() {
    const steps = [
      (Icons.folder_open, '1. Tap any .apk in Files / Downloads'),
      (Icons.open_in_new, '2. Choose "Open with RAT3"'),
      (Icons.layers, '3. RAT3 runs a 4-layer security scan'),
      (Icons.analytics, '4. A risk verdict is generated'),
      (Icons.check_circle_outline, '5. Safe → install • Risk → warning shown'),
    ];
    return InfoCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const SectionLabel('HOW IT WORKS'),
          const SizedBox(height: 12),
          for (final (icon, text) in steps)
            Padding(
              padding: const EdgeInsets.only(bottom: 8),
              child: Row(
                children: [
                  Icon(icon, size: 16, color: AppColors.primary),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      text,
                      style: const TextStyle(
                        color: AppColors.textSecondary,
                        fontSize: 13,
                      ),
                    ),
                  ),
                ],
              ),
            ),
        ],
      ),
    );
  }

  void _showAbout(BuildContext context) {
    showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: AppColors.surface,
        title: const Text(
          'About RAT3',
          style: TextStyle(color: AppColors.textPrimary),
        ),
        content: const Text(
          'RAT3 is a pre-installation APK security scanner.\n\n'
          'It runs a 4-layer static analysis:\n'
          '• Manifest / permission safety\n'
          '• Permission–function mismatch\n'
          '• Malware signatures & reputation\n'
          '• Heuristic risk model (rule-weighted, not a trained ML model)\n\n'
          'All analysis is local and offline. Installation is always user-approved.',
          style: TextStyle(color: AppColors.textMuted),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('OK', style: TextStyle(color: AppColors.primary)),
          ),
        ],
      ),
    );
  }
}
