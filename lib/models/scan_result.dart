/// Data models for APK scan results.
/// All data flows from Kotlin scanner via Platform Channels as JSON.

class ScanResult {
  final String apkPath;
  final String verdict;       // 'SAFE', 'SUSPICIOUS', 'MALICIOUS'
  final String summary;
  final int overallRiskScore; // 0–100
  final LayerResult layer1;
  final LayerResult layer2;
  final LayerResult layer3;
  final LayerResult layer4;

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
    return ScanResult(
      apkPath: json['apkPath'] ?? '',
      verdict: json['verdict'] ?? 'SAFE',
      summary: json['summary'] ?? '',
      overallRiskScore: json['overallRiskScore'] ?? 0,
      layer1: LayerResult.fromJson(json['layer1'] ?? {}),
      layer2: LayerResult.fromJson(json['layer2'] ?? {}),
      layer3: LayerResult.fromJson(json['layer3'] ?? {}),
      layer4: LayerResult.fromJson(json['layer4'] ?? {}),
    );
  }

  Map<String, dynamic> toJson() => {
        'apkPath': apkPath,
        'verdict': verdict,
        'summary': summary,
        'overallRiskScore': overallRiskScore,
        'layer1': layer1.toJson(),
        'layer2': layer2.toJson(),
        'layer3': layer3.toJson(),
        'layer4': layer4.toJson(),
      };
}

class LayerResult {
  final String layerName;
  final int riskScore;        // 0–100
  final List<Finding> findings;
  final Map<String, dynamic> rawData;

  LayerResult({
    required this.layerName,
    required this.riskScore,
    required this.findings,
    this.rawData = const {},
  });

  factory LayerResult.fromJson(Map<String, dynamic> json) {
    final findingsJson = json['findings'] as List<dynamic>? ?? [];
    return LayerResult(
      layerName: json['layerName'] ?? '',
      riskScore: json['riskScore'] ?? 0,
      findings: findingsJson
          .map((f) => Finding.fromJson(f as Map<String, dynamic>))
          .toList(),
      rawData: json['rawData'] as Map<String, dynamic>? ?? {},
    );
  }

  Map<String, dynamic> toJson() => {
        'layerName': layerName,
        'riskScore': riskScore,
        'findings': findings.map((f) => f.toJson()).toList(),
        'rawData': rawData,
      };
}

class Finding {
  final String message;
  final bool isWarning;
  final String? category;

  Finding({
    required this.message,
    this.isWarning = false,
    this.category,
  });

  factory Finding.fromJson(Map<String, dynamic> json) {
    return Finding(
      message: json['message'] ?? '',
      isWarning: json['isWarning'] ?? false,
      category: json['category'],
    );
  }

  Map<String, dynamic> toJson() => {
        'message': message,
        'isWarning': isWarning,
        'category': category,
      };
}