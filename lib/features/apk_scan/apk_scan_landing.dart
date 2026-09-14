import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../core/theme/app_theme.dart';
import '../../widgets/common_widgets.dart';
import 'scanning_screen.dart';
import 'services/apk_scanner_service.dart';

/// "Scan an APK" pane inside the Scanner tab — pick an APK and run the
/// 4-layer pre-installation scan (manifest, permission mismatch, signatures,
/// ML ensemble).
class ApkScanLanding extends StatelessWidget {
  const ApkScanLanding({super.key});

  static const _layers = [
    (
      icon: Icons.rule,
      name: 'App Safety Analysis',
      desc: 'Permissions, SDK, accessibility abuse',
    ),
    (
      icon: Icons.compare_arrows,
      name: 'Permission Mismatch',
      desc: 'Declared vs. actually used APIs',
    ),
    (
      icon: Icons.fingerprint,
      name: 'Malware Signatures',
      desc: 'Signatures, SHA-256 blocklist, signing',
    ),
    (
      icon: Icons.psychology,
      name: 'ML Malware Classifier',
      desc: '4-model ensemble (RF/DT/AdaBoost/XGBoost)',
    ),
  ];

  Future<void> _pick(BuildContext context) async {
    String? path;
    try {
      path = await ApkScannerService().pickApkFile();
    } on PlatformException catch (e) {
      if (!context.mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            'Could not open the file picker: ${e.message ?? e.code}',
          ),
        ),
      );
      return;
    }
    if (path == null || !context.mounted) return;
    final apkPath = path;
    await Navigator.of(context).push(
      MaterialPageRoute<void>(
        builder: (_) => ApkScanningScreen(apkPath: apkPath),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      padding: AppTheme.pagePadding,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          CyberCard(
            borderColor: AppTheme.neonCyan.withValues(alpha: 0.3),
            padding: const EdgeInsets.all(24),
            child: Column(
              children: [
                const Icon(
                  Icons.travel_explore,
                  size: 56,
                  color: AppTheme.neonCyan,
                ),
                const SizedBox(height: 12),
                Text(
                  'Scan an APK before installing',
                  style: AppTheme.headlineMedium,
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 6),
                Text(
                  'Pick an .apk from your device and RAT3 runs a 4-layer static '
                  'analysis, ending with an on-device ML malware classifier.',
                  style: AppTheme.bodyMedium,
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 20),
                SizedBox(
                  width: double.infinity,
                  child: ElevatedButton.icon(
                    onPressed: () => _pick(context),
                    icon: const Icon(Icons.upload_file),
                    label: const Text('SELECT APK FILE'),
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 24),
          const SectionHeader(title: 'Analysis Layers'),
          const SizedBox(height: 12),
          for (final l in _layers)
            Padding(
              padding: const EdgeInsets.only(bottom: 10),
              child: CyberCard(
                child: Row(
                  children: [
                    Icon(l.icon, color: AppTheme.neonGreen, size: 22),
                    const SizedBox(width: 14),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            l.name,
                            style: AppTheme.bodyLarge.copyWith(
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                          const SizedBox(height: 2),
                          Text(l.desc, style: AppTheme.labelSmall),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
            ),
          const SizedBox(height: 12),
          Text(
            'Tip: in your file manager, tap any .apk → "Scan with RAT3" to start '
            'this scan automatically.',
            style: AppTheme.labelSmall,
          ),
        ],
      ),
    );
  }
}
