import 'package:flutter/material.dart';

import '../models/scan_result.dart';
import '../theme/app_theme.dart';

/// Expandable card showing one layer's risk score and its list of findings.
class LayerFindingsCard extends StatelessWidget {
  const LayerFindingsCard({
    super.key,
    required this.title,
    required this.icon,
    required this.accent,
    required this.result,
  });

  final String title;
  final IconData icon;
  final Color accent;
  final LayerResult result;

  @override
  Widget build(BuildContext context) {
    final riskColor = AppColors.forScore(result.riskScore);
    return Container(
      margin: const EdgeInsets.only(bottom: 12),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: accent.withValues(alpha: 0.3)),
      ),
      child: ExpansionTile(
        tilePadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
        childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
        leading: Icon(icon, color: accent, size: 22),
        title: Text(
          title,
          style: const TextStyle(
            color: AppColors.textPrimary,
            fontSize: 13,
            fontWeight: FontWeight.w500,
          ),
        ),
        trailing: _RiskChip(score: result.riskScore, color: riskColor),
        children: [
          const Divider(color: AppColors.border),
          const SizedBox(height: 8),
          if (result.analysisError)
            const _FindingRow(
              Finding(
                message:
                    'This layer could not complete — findings are partial.',
                isWarning: true,
              ),
            ),
          ...result.findings.map(_FindingRow.new),
        ],
      ),
    );
  }
}

class _RiskChip extends StatelessWidget {
  const _RiskChip({required this.score, required this.color});

  final int score;
  final Color color;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.15),
        borderRadius: BorderRadius.circular(20),
      ),
      child: Text(
        '$score',
        style: TextStyle(
          color: color,
          fontWeight: FontWeight.bold,
          fontSize: 13,
        ),
      ),
    );
  }
}

class _FindingRow extends StatelessWidget {
  const _FindingRow(this.finding);

  final Finding finding;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 6),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(
            finding.isWarning ? Icons.warning_amber : Icons.info_outline,
            size: 14,
            color: finding.isWarning
                ? AppColors.suspicious
                : AppColors.textMuted,
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              finding.message,
              style: const TextStyle(
                color: AppColors.textSecondary,
                fontSize: 12,
              ),
            ),
          ),
        ],
      ),
    );
  }
}
