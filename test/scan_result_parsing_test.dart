import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:rat3/models/scan_result.dart';

void main() {
  group('ScanResult.fromJson', () {
    test('parses a complete result', () {
      final json =
          jsonDecode('''
      {
        "apkPath": "/data/app.apk",
        "verdict": "SUSPICIOUS",
        "summary": "some findings",
        "overallRiskScore": 42,
        "layer1": {"layerName": "App Safety Analysis", "riskScore": 30,
                   "findings": [{"message": "Dangerous permission: CAMERA", "isWarning": true}],
                   "rawData": {"analysisError": false}},
        "layer2": {"layerName": "Permission–Function Mismatch", "riskScore": 10, "findings": []},
        "layer3": {"layerName": "Malware Signature Check", "riskScore": 0, "findings": []},
        "layer4": {"layerName": "Heuristic Risk Model", "riskScore": 20, "findings": []}
      }
      ''')
              as Map<String, dynamic>;

      final result = ScanResult.fromJson(json);

      expect(result.verdict, 'SUSPICIOUS');
      expect(result.overallRiskScore, 42);
      expect(result.layers, hasLength(4));
      expect(result.layer1.findings.single.message, contains('CAMERA'));
      expect(result.layer1.findings.single.isWarning, isTrue);
      expect(result.layer1.analysisError, isFalse);
    });

    test('fills defaults for missing fields', () {
      final result = ScanResult.fromJson(<String, dynamic>{});

      expect(result.verdict, 'SAFE');
      expect(result.overallRiskScore, 0);
      expect(result.summary, isEmpty);
      expect(result.layers.every((l) => l.findings.isEmpty), isTrue);
    });

    test('accepts num (double) risk scores from the channel', () {
      final result = ScanResult.fromJson(<String, dynamic>{
        'overallRiskScore': 55.0,
        'layer1': <String, dynamic>{'riskScore': 12.7, 'findings': <dynamic>[]},
      });

      expect(result.overallRiskScore, 55);
      expect(result.layer1.riskScore, 13);
    });

    test('surfaces a layer analysis error flag', () {
      final result = ScanResult.fromJson(<String, dynamic>{
        'layer1': <String, dynamic>{
          'riskScore': 50,
          'findings': <dynamic>[],
          'rawData': <String, dynamic>{'analysisError': true},
        },
      });

      expect(result.layer1.analysisError, isTrue);
    });
  });
}
