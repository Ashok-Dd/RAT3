# RAT3 ProGuard Rules
# Keep scanner classes (needed for reflection-free operation)
-keep class com.example.rat3.scanner.** { *; }

# Keep MainActivity
-keep class com.example.rat3.MainActivity { *; }

# Flutter engine
-keep class io.flutter.** { *; }
-keep class io.flutter.embedding.** { *; }

# org.json (used for result serialization)
-keep class org.json.** { *; }

# Kotlin coroutines
-keepnames class kotlinx.coroutines.** { *; }