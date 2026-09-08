/// Data models for APK scan results. All data arrives from the Kotlin scanner as
/// JSON over a platform channel.
library;

int _asInt(Object? value) => switch (value) {
  final int v => v,
  final num v => v.round(),
  final String v => int.tryParse(v) ?? 0,
  _ => 0,
};

class ScanResult {
  ScanResult({
    required this.apkPath,
    required this.verdict,
    required this.summary,
    required this.overallRiskScore,
    required this.layer1,
    required this.layer2,
    required this.layer3,
    required this.layer4,
  });

  factory ScanResult.fromJson(Map<String, dynamic> json) {
    LayerResult layer(String key) => LayerResult.fromJson(
      (json[key] as Map?)?.cast<String, dynamic>() ?? const {},
    );
    return ScanResult(
      apkPath: json['apkPath'] as String? ?? '',
      verdict: json['verdict'] as String? ?? 'SAFE',
      summary: json['summary'] as String? ?? '',
      overallRiskScore: _asInt(json['overallRiskScore']),
      layer1: layer('layer1'),
      layer2: layer('layer2'),
      layer3: layer('layer3'),
      layer4: layer('layer4'),
    );
  }

  final String apkPath;

  /// One of `SAFE`, `SUSPICIOUS`, `MALICIOUS`.
  final String verdict;
  final String summary;

  /// 0–100.
  final int overallRiskScore;
  final LayerResult layer1;
  final LayerResult layer2;
  final LayerResult layer3;
  final LayerResult layer4;

  List<LayerResult> get layers => [layer1, layer2, layer3, layer4];
}

class LayerResult {
  LayerResult({
    required this.layerName,
    required this.riskScore,
    required this.findings,
    this.analysisError = false,
  });

  factory LayerResult.fromJson(Map<String, dynamic> json) {
    final rawFindings = json['findings'] as List<dynamic>? ?? const [];
    final rawData =
        (json['rawData'] as Map?)?.cast<String, dynamic>() ?? const {};
    return LayerResult(
      layerName: json['layerName'] as String? ?? '',
      riskScore: _asInt(json['riskScore']),
      findings: rawFindings
          .map((f) => Finding.fromJson((f as Map).cast<String, dynamic>()))
          .toList(),
      analysisError: rawData['analysisError'] as bool? ?? false,
    );
  }

  final String layerName;
  final int riskScore;
  final List<Finding> findings;
  final bool analysisError;
}

class Finding {
  const Finding({required this.message, this.isWarning = false, this.category});

  factory Finding.fromJson(Map<String, dynamic> json) => Finding(
    message: json['message'] as String? ?? '',
    isWarning: json['isWarning'] as bool? ?? false,
    category: json['category'] as String?,
  );

  final String message;
  final bool isWarning;
  final String? category;
}
