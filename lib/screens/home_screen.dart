import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../services/apk_scanner_service.dart';
import 'scanning_screen.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  final ApkScannerService _scanner = ApkScannerService();

  // Same channel Kotlin uses — we listen here for warm-start "Open with RAT3"
  static const _fileChannel = MethodChannel('com.example.rat3/file');

  @override
  void initState() {
    super.initState();

    // If the user opens a second APK while the app is already running
    // (warm start), Kotlin calls onIncomingApk on this channel.
    // main.dart handles cold-start; this handles warm-start on HomeScreen.
    _fileChannel.setMethodCallHandler((call) async {
      if (call.method == 'onIncomingApk') {
        final args = call.arguments;
        final apkPath = args is Map ? args['apkPath'] as String? : null;
        if (apkPath != null && apkPath.isNotEmpty && mounted) {
          _goToScan(apkPath);
        }
      }
    });
  }

  void _goToScan(String apkPath) {
    Navigator.of(context).push(
      MaterialPageRoute(builder: (_) => ScanningScreen(apkPath: apkPath)),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0D1117),
      appBar: AppBar(
        backgroundColor: const Color(0xFF161B22),
        title: const Row(
          children: [
            Icon(Icons.security, color: Color(0xFF00E5FF), size: 24),
            SizedBox(width: 8),
            Text(
              'RAT3',
              style: TextStyle(
                color: Color(0xFF00E5FF),
                fontWeight: FontWeight.bold,
                letterSpacing: 3,
              ),
            ),
          ],
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.info_outline, color: Color(0xFF8B949E)),
            onPressed: _showAboutDialog,
          ),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _buildStatusCard(),
            const SizedBox(height: 24),
            _buildScanCard(),
            const SizedBox(height: 24),
            _buildLayersOverview(),
            const SizedBox(height: 24),
            _buildHowItWorks(),
          ],
        ),
      ),
    );
  }

  Widget _buildStatusCard() {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: const Color(0xFF161B22),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: const Color(0xFF1DE9B6).withOpacity(0.3)),
      ),
      child: const Row(
        children: [
          _PulseDot(),
          SizedBox(width: 12),
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'All Security Modules Active',
                style: TextStyle(
                  color: Color(0xFF1DE9B6),
                  fontWeight: FontWeight.w600,
                ),
              ),
              Text(
                '4 layers ready • Open an APK to scan',
                style: TextStyle(color: Color(0xFF8B949E), fontSize: 12),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildScanCard() {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(32),
      decoration: BoxDecoration(
        color: const Color(0xFF161B22),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: const Color(0xFF00E5FF).withOpacity(0.2)),
        boxShadow: [
          BoxShadow(
            color: const Color(0xFF00E5FF).withOpacity(0.05),
            blurRadius: 20,
            spreadRadius: 2,
          ),
        ],
      ),
      child: Column(
        children: [
          const Icon(Icons.find_in_page_outlined, size: 64, color: Color(0xFF00E5FF)),
          const SizedBox(height: 16),
          const Text(
            'Scan APK File',
            style: TextStyle(fontSize: 22, fontWeight: FontWeight.bold, color: Colors.white),
          ),
          const SizedBox(height: 8),
          const Text(
            'Select an APK file to perform a comprehensive\n4-layer security analysis before installation.',
            textAlign: TextAlign.center,
            style: TextStyle(color: Color(0xFF8B949E), fontSize: 13),
          ),
          const SizedBox(height: 28),
          SizedBox(
            width: double.infinity,
            height: 52,
            child: ElevatedButton.icon(
              onPressed: _pickAndScanApk,
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
                backgroundColor: const Color(0xFF00E5FF),
                foregroundColor: const Color(0xFF0D1117),
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
              ),
            ),
          ),
          const SizedBox(height: 16),
          // Visual hint for "Open with" flow
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
            decoration: BoxDecoration(
              color: const Color(0xFF0D1117),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: const Color(0xFF30363D)),
            ),
            child: const Row(
              children: [
                Icon(Icons.folder_open, size: 16, color: Color(0xFF00E5FF)),
                SizedBox(width: 10),
                Expanded(
                  child: Text(
                    'Or tap any APK in your file manager → "Open with RAT3" → scan starts automatically',
                    style: TextStyle(color: Color(0xFF8B949E), fontSize: 11),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildLayersOverview() {
    final layers = [
      {'icon': Icons.rule,           'title': 'Layer 1', 'subtitle': 'App Safety Analysis',  'color': const Color(0xFF00E5FF)},
      {'icon': Icons.compare_arrows, 'title': 'Layer 2', 'subtitle': 'Permission Mismatch',  'color': const Color(0xFFFFD600)},
      {'icon': Icons.fingerprint,    'title': 'Layer 3', 'subtitle': 'Malware Signatures',   'color': const Color(0xFFFF6D00)},
      {'icon': Icons.psychology,     'title': 'Layer 4', 'subtitle': 'ML Prediction',        'color': const Color(0xFF1DE9B6)},
    ];

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'SECURITY LAYERS',
          style: TextStyle(color: Color(0xFF8B949E), fontSize: 11, fontWeight: FontWeight.w600, letterSpacing: 2),
        ),
        const SizedBox(height: 12),
        GridView.builder(
          shrinkWrap: true,
          physics: const NeverScrollableScrollPhysics(),
          gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
            crossAxisCount: 2,
            mainAxisSpacing: 12,
            crossAxisSpacing: 12,
            childAspectRatio: 2.2,
          ),
          itemCount: layers.length,
          itemBuilder: (context, i) {
            final layer = layers[i];
            return Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: const Color(0xFF161B22),
                borderRadius: BorderRadius.circular(10),
                border: Border.all(color: (layer['color'] as Color).withOpacity(0.3)),
              ),
              child: Row(
                children: [
                  Icon(layer['icon'] as IconData, color: layer['color'] as Color, size: 22),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Text(layer['title'] as String,
                            style: TextStyle(color: layer['color'] as Color, fontSize: 11, fontWeight: FontWeight.w600)),
                        Text(layer['subtitle'] as String,
                            style: const TextStyle(color: Color(0xFF8B949E), fontSize: 10),
                            overflow: TextOverflow.ellipsis),
                      ],
                    ),
                  ),
                ],
              ),
            );
          },
        ),
      ],
    );
  }

  Widget _buildHowItWorks() {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: const Color(0xFF161B22),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: const Color(0xFF30363D)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text('HOW IT WORKS',
              style: TextStyle(color: Color(0xFF8B949E), fontSize: 11, fontWeight: FontWeight.w600, letterSpacing: 2)),
          const SizedBox(height: 12),
          ..._step(Icons.folder_open,        '1. Tap any .apk in Files / Downloads'),
          ..._step(Icons.open_in_new,        '2. Choose "Open with RAT3"'),
          ..._step(Icons.layers,             '3. RAT3 runs 4-layer deep security scan automatically'),
          ..._step(Icons.analytics,          '4. AI-powered verdict generated'),
          ..._step(Icons.check_circle_outline,'5. Safe → Install  |  Risk → Warning shown'),
        ],
      ),
    );
  }

  List<Widget> _step(IconData icon, String text) => [
    Row(
      children: [
        Icon(icon, size: 16, color: const Color(0xFF00E5FF)),
        const SizedBox(width: 10),
        Expanded(
          child: Text(text, style: const TextStyle(color: Color(0xFFCDD9E5), fontSize: 13)),
        ),
      ],
    ),
    const SizedBox(height: 8),
  ];

  Future<void> _pickAndScanApk() async {
    final apkPath = await _scanner.pickApkFile();
    if (apkPath == null || !mounted) return;
    _goToScan(apkPath);
  }

  void _showAboutDialog() {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF161B22),
        title: const Text('About RAT3', style: TextStyle(color: Colors.white)),
        content: const Text(
          'RAT3 is a pre-installation APK security scanner.\n\n'
          'It performs 4-layer analysis:\n'
          '• Manifest safety analysis\n'
          '• Permission mismatch detection\n'
          '• Malware signature matching\n'
          '• Machine learning prediction\n\n'
          'All analysis is local and offline.\n'
          'Installation is always user-approved.',
          style: TextStyle(color: Color(0xFF8B949E)),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('OK', style: TextStyle(color: Color(0xFF00E5FF))),
          ),
        ],
      ),
    );
  }
}

// Simple animated pulsing dot for the status card
class _PulseDot extends StatefulWidget {
  const _PulseDot();
  @override
  State<_PulseDot> createState() => _PulseDotState();
}

class _PulseDotState extends State<_PulseDot> with SingleTickerProviderStateMixin {
  late AnimationController _c;
  late Animation<double> _a;

  @override
  void initState() {
    super.initState();
    _c = AnimationController(vsync: this, duration: const Duration(seconds: 1))
      ..repeat(reverse: true);
    _a = Tween(begin: 0.4, end: 1.0).animate(_c);
  }

  @override
  void dispose() { _c.dispose(); super.dispose(); }

  @override
  Widget build(BuildContext context) => FadeTransition(
    opacity: _a,
    child: Container(
      width: 12, height: 12,
      decoration: const BoxDecoration(shape: BoxShape.circle, color: Color(0xFF1DE9B6)),
    ),
  );
}