import 'dart:async';
import 'package:rat3/core/constants/app_constants.dart';
import 'package:rat3/core/utils/app_utils.dart';
import 'package:rat3/data/models/app_models.dart';
import 'package:rat3/data/services/platform_channel_service.dart';
import 'package:rat3/data/services/storage_service.dart';
import 'package:rat3/layers/alert_engine/alert_engine.dart';
import 'package:rat3/layers/feature_engine/device_features.dart';
import 'package:rat3/layers/feature_engine/feature_collector.dart';
import 'package:rat3/layers/feature_engine/rule_based_scorer.dart';
import 'package:rat3/layers/network_monitor/network_monitor.dart';

/// Layer 5 – Risk Scoring & Decision Engine  (Feature-based rewrite)
///
/// Flow:
///   1. FeatureCollector.collect()  → DeviceFeatures (60+ signals)
///   2. RuleBasedScorer.score()     → ScoredResult (6 sub-scores + rules)
///   3. RiskScore emitted           → Dashboard + AlertEngine
///
/// Weights:
///   Sensor Behavior   25%
///   Network/Resource  25%
///   App Behavior      20%
///   System Security   15%
///   Permission Abuse  10%
///   Aggregated         5%
class RiskEngine {
  static const String _tag = 'RiskEngine';

  final PlatformChannelService _platform;
  final NetworkMonitor         _networkMonitor;
  final StorageService         _storageService;
  final AlertEngine            _alertEngine;

  late final FeatureCollector _collector;
  final      RuleBasedScorer  _scorer = RuleBasedScorer();

  final _scoreController = StreamController<RiskScore>.broadcast();
  Stream<RiskScore> get scoreStream => _scoreController.stream;

  Timer?    _recalcTimer;
  RiskScore _currentScore    = RiskScore.initial;
  DeviceFeatures _lastFeatures = DeviceFeatures.empty();

  RiskScore     get currentScore => _currentScore;
  DeviceFeatures get lastFeatures => _lastFeatures;

  RiskEngine({
    required PlatformChannelService platform,
    required NetworkMonitor networkMonitor,
    required StorageService storageService,
    required AlertEngine alertEngine,
  })  : _platform       = platform,
        _networkMonitor  = networkMonitor,
        _storageService  = storageService,
        _alertEngine     = alertEngine {
    _collector = FeatureCollector(
      platform:       platform,
      networkMonitor: networkMonitor,
    );
  }

  /// Start automatic recalculation every 60 seconds.
  void start() {
    final saved = _storageService.loadRiskScore();
    AppLogger.info(_tag, 'Risk engine started (saved score: $saved)');
    _recalcTimer = Timer.periodic(const Duration(seconds: 60), (_) {
      recalculate();
    });
  }

  void stop() {
    _recalcTimer?.cancel();
    _recalcTimer = null;
  }

  /// Full feature-based recalculation. Called after every scan.
  Future<void> recalculate() async {
    try {
      AppLogger.info(_tag, 'Collecting features…');
      final features = await _collector.collect();
      _lastFeatures  = features;

      AppLogger.info(_tag, 'Scoring features…');
      final result = _scorer.score(features);

      AppLogger.info(_tag,
          'Score: ${result.composite} [${_levelForScore(result.composite).label}] '
          '— ${result.breakdown}');
      AppLogger.info(_tag,
          'Rules triggered: ${result.triggeredRules.length}');

      _currentScore = _buildScore(result);
      _storageService.saveRiskScore(_currentScore.score);

      // Inject rule-triggered alerts into the alert engine
      _injectRuleAlerts(result, features);

      if (!_scoreController.isClosed) {
        _scoreController.add(_currentScore);
      }
    } catch (e, st) {
      AppLogger.error(_tag, 'recalculate error', e, st);
    }
  }

  // ── Alert injection ────────────────────────────────────────────────────────

  void _injectRuleAlerts(ScoredResult result, DeviceFeatures f) {
    // Only inject critical and high alerts — medium/low are too noisy
    for (final rule in result.highPriorityRules) {
      final alert = AlertEvent(
        // ID is deterministic so alert engine dedup fires correctly
        id:       'risk_rule_${rule.title.replaceAll(' ', '_').toLowerCase()}',
        severity: rule.severity,
        title:    rule.title,
        description: rule.description,
        userFriendlyMessage: rule.description,
        timestamp: f.collectedAt,
        source:   'Risk Engine',
      );
      _alertEngine.injectAlert(alert);
    }
  }

  // ── Score building ─────────────────────────────────────────────────────────

  RiskScore _buildScore(ScoredResult result) {
    final level = _levelForScore(result.composite);
    return RiskScore(
      score:                  result.composite,
      level:                  level,
      runtimeContribution:    result.systemScore.toDouble(),
      networkContribution:    result.networkScore.toDouble(),
      permissionContribution: result.permissionScore.toDouble(),
      // Extended sub-scores stored in the extra fields
      sensorContribution:     result.sensorScore.toDouble(),
      appContribution:        result.appScore.toDouble(),
      aggregatedContribution: result.aggregatedScore.toDouble(),
      calculatedAt:           DateTime.now(),
    );
  }

  RiskLevel _levelForScore(int score) {
    if (score <= AppConstants.safeThreshold)       return RiskLevel.safe;
    if (score <= AppConstants.suspiciousThreshold) return RiskLevel.suspicious;
    return RiskLevel.dangerous;
  }

  void dispose() {
    stop();
    _scoreController.close();
  }
}