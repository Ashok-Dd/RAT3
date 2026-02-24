import 'package:flutter/material.dart';
import '../models/scan_result.dart';
import '../services/apk_scanner_service.dart';

class ResultScreen extends StatelessWidget {
  final ScanResult result;
  const ResultScreen({super.key, required this.result});

  @override
  Widget build(BuildContext context) {
    final isSafe = result.verdict == 'SAFE';
    final isSuspicious = result.verdict == 'SUSPICIOUS';
    final verdictColor = isSafe
        ? const Color(0xFF1DE9B6)
        : isSuspicious
            ? const Color(0xFFFFD600)
            : const Color(0xFFFF4444);

    return Scaffold(
      backgroundColor: const Color(0xFF0D1117),
      appBar: AppBar(
        backgroundColor: const Color(0xFF161B22),
        title: const Text('Scan Result', style: TextStyle(color: Colors.white)),
        leading: IconButton(
          icon: const Icon(Icons.arrow_back, color: Colors.white),
          onPressed: () => Navigator.of(context).pop(),
        ),
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(20),
        child: Column(
          children: [
            // Verdict card
            _buildVerdictCard(verdictColor, isSafe),
            const SizedBox(height: 20),
            // Risk score bar
            _buildRiskScoreCard(),
            const SizedBox(height: 20),
            // Layer results
            _buildLayerResults(),
            const SizedBox(height: 24),
            // Action buttons
            _buildActionButtons(context, isSafe),
            const SizedBox(height: 20),
          ],
        ),
      ),
    );
  }

  Widget _buildVerdictCard(Color verdictColor, bool isSafe) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(24),
      decoration: BoxDecoration(
        color: const Color(0xFF161B22),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: verdictColor.withOpacity(0.5)),
        boxShadow: [
          BoxShadow(
            color: verdictColor.withOpacity(0.1),
            blurRadius: 20,
            spreadRadius: 2,
          ),
        ],
      ),
      child: Column(
        children: [
          Icon(
            isSafe ? Icons.verified_user : Icons.gpp_bad,
            size: 64,
            color: verdictColor,
          ),
          const SizedBox(height: 12),
          Text(
            result.verdict,
            style: TextStyle(
              fontSize: 32,
              fontWeight: FontWeight.bold,
              color: verdictColor,
              letterSpacing: 3,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            result.summary,
            textAlign: TextAlign.center,
            style: const TextStyle(color: Color(0xFF8B949E), fontSize: 13),
          ),
        ],
      ),
    );
  }

  Widget _buildRiskScoreCard() {
    final score = result.overallRiskScore;
    final scoreColor = score < 33
        ? const Color(0xFF1DE9B6)
        : score < 66
            ? const Color(0xFFFFD600)
            : const Color(0xFFFF4444);

    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: const Color(0xFF161B22),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: const Color(0xFF30363D)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              const Text(
                'OVERALL RISK SCORE',
                style: TextStyle(
                  color: Color(0xFF8B949E),
                  fontSize: 11,
                  fontWeight: FontWeight.w600,
                  letterSpacing: 2,
                ),
              ),
              Text(
                '$score / 100',
                style: TextStyle(
                  color: scoreColor,
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
              backgroundColor: const Color(0xFF0D1117),
              valueColor: AlwaysStoppedAnimation<Color>(scoreColor),
              minHeight: 8,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildLayerResults() {
    final layers = [
      {
        'title': 'Layer 1: App Safety Analysis',
        'result': result.layer1,
        'icon': Icons.rule,
        'color': const Color(0xFF00E5FF),
      },
      {
        'title': 'Layer 2: Permission Mismatch',
        'result': result.layer2,
        'icon': Icons.compare_arrows,
        'color': const Color(0xFFFFD600),
      },
      {
        'title': 'Layer 3: Malware Signatures',
        'result': result.layer3,
        'icon': Icons.fingerprint,
        'color': const Color(0xFFFF6D00),
      },
      {
        'title': 'Layer 4: ML Prediction',
        'result': result.layer4,
        'icon': Icons.psychology,
        'color': const Color(0xFF1DE9B6),
      },
    ];

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'LAYER ANALYSIS',
          style: TextStyle(
            color: Color(0xFF8B949E),
            fontSize: 11,
            fontWeight: FontWeight.w600,
            letterSpacing: 2,
          ),
        ),
        const SizedBox(height: 12),
        ...layers.map((l) => _buildLayerCard(l)).toList(),
      ],
    );
  }

  Widget _buildLayerCard(Map<String, dynamic> data) {
    final layerResult = data['result'] as LayerResult;
    final riskColor = layerResult.riskScore < 33
        ? const Color(0xFF1DE9B6)
        : layerResult.riskScore < 66
            ? const Color(0xFFFFD600)
            : const Color(0xFFFF4444);

    return Container(
      margin: const EdgeInsets.only(bottom: 12),
      decoration: BoxDecoration(
        color: const Color(0xFF161B22),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(
          color: (data['color'] as Color).withOpacity(0.3),
        ),
      ),
      child: ExpansionTile(
        tilePadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
        childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
        leading: Icon(data['icon'] as IconData,
            color: data['color'] as Color, size: 22),
        title: Text(
          data['title'] as String,
          style: const TextStyle(
            color: Colors.white,
            fontSize: 13,
            fontWeight: FontWeight.w500,
          ),
        ),
        trailing: Container(
          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
          decoration: BoxDecoration(
            color: riskColor.withOpacity(0.15),
            borderRadius: BorderRadius.circular(20),
          ),
          child: Text(
            '${layerResult.riskScore}',
            style: TextStyle(
              color: riskColor,
              fontWeight: FontWeight.bold,
              fontSize: 13,
            ),
          ),
        ),
        children: [
          const Divider(color: Color(0xFF30363D)),
          const SizedBox(height: 8),
          ...layerResult.findings.map(
            (f) => Padding(
              padding: const EdgeInsets.only(bottom: 6),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Icon(
                    f.isWarning ? Icons.warning_amber : Icons.info_outline,
                    size: 14,
                    color: f.isWarning
                        ? const Color(0xFFFFD600)
                        : const Color(0xFF8B949E),
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      f.message,
                      style: const TextStyle(
                        color: Color(0xFFCDD9E5),
                        fontSize: 12,
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildActionButtons(BuildContext context, bool isSafe) {
    if (isSafe) {
      return Column(
        children: [
          SizedBox(
            width: double.infinity,
            height: 52,
            child: ElevatedButton.icon(
              onPressed: () => _proceedWithInstall(context),
              icon: const Icon(Icons.install_mobile),
              label: const Text(
                'INSTALL APK',
                style: TextStyle(
                  fontWeight: FontWeight.bold,
                  letterSpacing: 1.5,
                ),
              ),
              style: ElevatedButton.styleFrom(
                backgroundColor: const Color(0xFF1DE9B6),
                foregroundColor: const Color(0xFF0D1117),
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(10),
                ),
              ),
            ),
          ),
          const SizedBox(height: 12),
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text(
              'Cancel',
              style: TextStyle(color: Color(0xFF8B949E)),
            ),
          ),
        ],
      );
    } else {
      return Column(
        children: [
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: const Color(0xFFFF4444).withOpacity(0.1),
              borderRadius: BorderRadius.circular(10),
              border: Border.all(
                  color: const Color(0xFFFF4444).withOpacity(0.4)),
            ),
            child: Row(
              children: [
                const Icon(Icons.warning_amber,
                    color: Color(0xFFFF4444), size: 20),
                const SizedBox(width: 10),
                const Expanded(
                  child: Text(
                    'This APK has been flagged as potentially dangerous. '
                    'Installation is not recommended.',
                    style:
                        TextStyle(color: Color(0xFFFF9999), fontSize: 12),
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
              onPressed: () => _showRiskyInstallDialog(context),
              icon: const Icon(Icons.warning_amber,
                  color: Color(0xFFFF4444)),
              label: const Text(
                'INSTALL ANYWAY (RISK)',
                style: TextStyle(
                  color: Color(0xFFFF4444),
                  fontWeight: FontWeight.bold,
                  letterSpacing: 1.2,
                ),
              ),
              style: OutlinedButton.styleFrom(
                side: const BorderSide(color: Color(0xFFFF4444)),
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(10),
                ),
              ),
            ),
          ),
          const SizedBox(height: 12),
          SizedBox(
            width: double.infinity,
            height: 52,
            child: ElevatedButton.icon(
              onPressed: () => Navigator.of(context).pop(),
              icon: const Icon(Icons.cancel),
              label: const Text(
                'CANCEL INSTALLATION',
                style: TextStyle(
                  fontWeight: FontWeight.bold,
                  letterSpacing: 1.2,
                ),
              ),
              style: ElevatedButton.styleFrom(
                backgroundColor: const Color(0xFF1DE9B6),
                foregroundColor: const Color(0xFF0D1117),
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(10),
                ),
              ),
            ),
          ),
        ],
      );
    }
  }

  Future<void> _showRiskyInstallDialog(BuildContext context) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF161B22),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        title: const Row(
          children: [
            Icon(Icons.gpp_bad, color: Color(0xFFFF4444)),
            SizedBox(width: 8),
            Text('Security Warning',
                style: TextStyle(color: Colors.white, fontSize: 18)),
          ],
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'RAT3 has detected threats in this APK:',
              style: TextStyle(color: Color(0xFF8B949E)),
            ),
            const SizedBox(height: 12),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: const Color(0xFFFF4444).withOpacity(0.08),
                borderRadius: BorderRadius.circular(8),
                border:
                    Border.all(color: const Color(0xFFFF4444).withOpacity(0.3)),
              ),
              child: Text(
                result.summary,
                style:
                    const TextStyle(color: Color(0xFFFF9999), fontSize: 12),
              ),
            ),
            const SizedBox(height: 16),
            const Text(
              'By proceeding, you accept all responsibility for any damage caused. '
              'This action is strongly discouraged.',
              style: TextStyle(color: Color(0xFF8B949E), fontSize: 12),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Cancel',
                style: TextStyle(color: Color(0xFF1DE9B6))),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(ctx, true),
            style: ElevatedButton.styleFrom(
              backgroundColor: const Color(0xFFFF4444),
            ),
            child: const Text('Install Anyway'),
          ),
        ],
      ),
    );
    if (confirmed == true && context.mounted) {
      _proceedWithInstall(context);
    }
  }

  Future<void> _proceedWithInstall(BuildContext context) async {
    await ApkScannerService().installApk(result.apkPath);
  }
}