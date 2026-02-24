import 'package:flutter/material.dart';
import '../services/apk_scanner_service.dart';
import '../models/scan_result.dart';
import 'result_screen.dart';

class ScanningScreen extends StatefulWidget {
  final String apkPath;
  const ScanningScreen({super.key, required this.apkPath});

  @override
  State<ScanningScreen> createState() => _ScanningScreenState();
}

class _ScanningScreenState extends State<ScanningScreen>
    with TickerProviderStateMixin {
  final ApkScannerService _service = ApkScannerService();

  int _currentLayer = 0;
  String _statusMessage = 'Initializing scan...';
  bool _isComplete = false;

  final List<LayerStatus> _layers = [
    LayerStatus(
      name: 'App Safety Analysis',
      description: 'Scanning manifest, permissions, SDK...',
      icon: Icons.rule,
      color: const Color(0xFF00E5FF),
    ),
    LayerStatus(
      name: 'Permission Mismatch',
      description: 'Mapping permissions to API usage...',
      icon: Icons.compare_arrows,
      color: const Color(0xFFFFD600),
    ),
    LayerStatus(
      name: 'Malware Signatures',
      description: 'Checking against signature database...',
      icon: Icons.fingerprint,
      color: const Color(0xFFFF6D00),
    ),
    LayerStatus(
      name: 'ML Prediction',
      description: 'Running AI threat model...',
      icon: Icons.psychology,
      color: const Color(0xFF1DE9B6),
    ),
  ];

  @override
  void initState() {
    super.initState();
    _startScan();
  }

  Future<void> _startScan() async {
    try {
      final result = await _service.scanApk(
        apkPath: widget.apkPath,
        onLayerComplete: (layer) {
          setState(() {
            _currentLayer = layer + 1;
            _layers[layer].status = LayerStatusType.complete;
            if (layer + 1 < _layers.length) {
              _layers[layer + 1].status = LayerStatusType.scanning;
              _statusMessage = _layers[layer + 1].description;
            }
          });
        },
      );

      setState(() => _isComplete = true);

      if (!mounted) return;
      await Future.delayed(const Duration(milliseconds: 800));
      Navigator.of(context).pushReplacement(
        MaterialPageRoute(
          builder: (_) => ResultScreen(result: result),
        ),
      );
    } catch (e) {
      setState(() => _statusMessage = 'Scan failed: $e');
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0D1117),
      appBar: AppBar(
        backgroundColor: const Color(0xFF161B22),
        title: const Text(
          'Scanning APK',
          style: TextStyle(color: Colors.white),
        ),
        automaticallyImplyLeading: false,
      ),
      body: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // APK path info
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: const Color(0xFF161B22),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: const Color(0xFF30363D)),
              ),
              child: Row(
                children: [
                  const Icon(Icons.android, color: Color(0xFF1DE9B6), size: 20),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      widget.apkPath.split('/').last,
                      style: const TextStyle(
                        color: Color(0xFFCDD9E5),
                        fontSize: 13,
                      ),
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 32),

            const Text(
              'SECURITY ANALYSIS',
              style: TextStyle(
                color: Color(0xFF8B949E),
                fontSize: 11,
                fontWeight: FontWeight.w600,
                letterSpacing: 2,
              ),
            ),
            const SizedBox(height: 16),

            // Layer progress list
            Expanded(
              child: ListView.separated(
                itemCount: _layers.length,
                separatorBuilder: (_, __) => const SizedBox(height: 16),
                itemBuilder: (_, i) => _buildLayerCard(_layers[i], i),
              ),
            ),

            const SizedBox(height: 24),

            // Status message
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: const Color(0xFF161B22),
                borderRadius: BorderRadius.circular(10),
              ),
              child: Row(
                children: [
                  if (!_isComplete)
                    const SizedBox(
                      width: 16,
                      height: 16,
                      child: CircularProgressIndicator(
                        strokeWidth: 2,
                        color: Color(0xFF00E5FF),
                      ),
                    ),
                  if (_isComplete)
                    const Icon(Icons.check_circle,
                        color: Color(0xFF1DE9B6), size: 16),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Text(
                      _isComplete ? 'Analysis complete!' : _statusMessage,
                      style: const TextStyle(
                        color: Color(0xFFCDD9E5),
                        fontSize: 13,
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildLayerCard(LayerStatus layer, int index) {
    Color borderColor;
    Widget statusWidget;

    switch (layer.status) {
      case LayerStatusType.waiting:
        borderColor = const Color(0xFF30363D);
        statusWidget = const Icon(
          Icons.radio_button_unchecked,
          color: Color(0xFF8B949E),
          size: 20,
        );
        break;
      case LayerStatusType.scanning:
        borderColor = layer.color;
        statusWidget = SizedBox(
          width: 20,
          height: 20,
          child: CircularProgressIndicator(
            strokeWidth: 2,
            color: layer.color,
          ),
        );
        break;
      case LayerStatusType.complete:
        borderColor = const Color(0xFF1DE9B6);
        statusWidget = const Icon(
          Icons.check_circle,
          color: Color(0xFF1DE9B6),
          size: 20,
        );
        break;
    }

    return AnimatedContainer(
      duration: const Duration(milliseconds: 300),
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: const Color(0xFF161B22),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: borderColor),
      ),
      child: Row(
        children: [
          Container(
            width: 40,
            height: 40,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: layer.color.withOpacity(0.1),
            ),
            child: Icon(layer.icon, color: layer.color, size: 22),
          ),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Layer ${index + 1}: ${layer.name}',
                  style: TextStyle(
                    color: layer.status == LayerStatusType.waiting
                        ? const Color(0xFF8B949E)
                        : Colors.white,
                    fontWeight: FontWeight.w600,
                    fontSize: 14,
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  layer.description,
                  style: const TextStyle(
                    color: Color(0xFF8B949E),
                    fontSize: 11,
                  ),
                ),
              ],
            ),
          ),
          statusWidget,
        ],
      ),
    );
  }
}

enum LayerStatusType { waiting, scanning, complete }

class LayerStatus {
  final String name;
  final String description;
  final IconData icon;
  final Color color;
  LayerStatusType status;

  LayerStatus({
    required this.name,
    required this.description,
    required this.icon,
    required this.color,
    this.status = LayerStatusType.waiting,
  });
}