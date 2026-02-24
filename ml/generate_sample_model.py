"""
RAT3 Sample Model Generator
============================

Generates a dummy sklearn model (sample_model.pkl) for development purposes.

This is NOT a trained malware detection model.
It simply demonstrates the interface and feature schema.

Run this script once to produce sample_model.pkl:
    python generate_sample_model.py

Replace with real_model.pkl (trained on real APK data) for production.
See ml/feature_schema.md for training instructions.
"""

import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

# Feature names (index must match feature_schema.md)
FEATURE_NAMES = [
    "numPermissions",
    "numDangerousPermissions",
    "numSuspiciousPermissions",
    "numExportedComponents",
    "targetSdk",
    "hasSmsPermission",
    "hasCameraPermission",
    "hasLocationPermission",
    "hasAudioPermission",
    "numNativeLibs",
    "hasObfuscation",
    "dexSizeKB",
    "numBase64Blobs",
    "hasRawIpAddresses",
    "layer1RiskScore",
    "layer2RiskScore",
    "layer3RiskScore",
]

def generate_dummy_data(n_samples=500, random_state=42):
    """
    Creates synthetic APK feature vectors for demonstration.
    In production, replace with real APK feature extraction.
    """
    rng = np.random.RandomState(random_state)
    X = []
    y = []

    for _ in range(n_samples):
        label = rng.choice([0, 1, 2], p=[0.6, 0.25, 0.15])  # SAFE, SUSPICIOUS, MALICIOUS

        if label == 0:  # SAFE
            sample = [
                rng.randint(2, 12),   # numPermissions
                rng.randint(0, 5),    # numDangerous
                rng.randint(0, 2),    # numSuspicious
                rng.randint(0, 2),    # exportedComponents
                rng.randint(28, 34),  # targetSdk (modern)
                0,                    # hasSms
                rng.randint(0, 2),    # hasCamera
                rng.randint(0, 2),    # hasLocation
                0,                    # hasAudio
                rng.randint(0, 2),    # nativeLibs
                0,                    # obfuscation
                rng.uniform(100, 3000),  # dexSizeKB
                rng.randint(0, 3),    # base64Blobs
                0,                    # rawIPs
                rng.randint(0, 25),   # layer1Score
                rng.randint(0, 20),   # layer2Score
                rng.randint(0, 15),   # layer3Score
            ]
        elif label == 1:  # SUSPICIOUS
            sample = [
                rng.randint(8, 20),
                rng.randint(4, 10),
                rng.randint(2, 6),
                rng.randint(1, 4),
                rng.randint(21, 30),  # older SDK
                rng.randint(0, 2),
                rng.randint(0, 2),
                1,
                rng.randint(0, 2),
                rng.randint(1, 5),
                rng.randint(0, 2),
                rng.uniform(500, 8000),
                rng.randint(3, 10),
                rng.randint(0, 2),
                rng.randint(25, 55),
                rng.randint(20, 50),
                rng.randint(15, 45),
            ]
        else:  # MALICIOUS
            sample = [
                rng.randint(10, 30),
                rng.randint(6, 15),
                rng.randint(3, 8),
                rng.randint(2, 8),
                rng.randint(15, 26),  # very old SDK
                1,                    # always has SMS
                rng.randint(0, 2),
                1,                    # always has location
                1,                    # always has audio
                rng.randint(2, 10),
                1,                    # obfuscated
                rng.uniform(1000, 15000),
                rng.randint(8, 30),
                1,                    # always has raw IPs
                rng.randint(55, 100),
                rng.randint(45, 90),
                rng.randint(60, 100),
            ]

        X.append(sample)
        y.append(label)

    return np.array(X, dtype=float), np.array(y, dtype=int)


def main():
    print("Generating dummy training data...")
    X, y = generate_dummy_data(n_samples=1000)

    print(f"  Samples: {len(X)}")
    print(f"  Classes: SAFE={sum(y==0)}, SUSPICIOUS={sum(y==1)}, MALICIOUS={sum(y==2)}")

    print("\nTraining sample model...")
    model = Pipeline([
        ('scaler', StandardScaler()),
        ('clf', RandomForestClassifier(
            n_estimators=50,
            max_depth=8,
            class_weight='balanced',
            random_state=42,
        ))
    ])
    model.fit(X, y)

    # Quick accuracy check
    preds = model.predict(X)
    accuracy = (preds == y).mean()
    print(f"  Training accuracy (dummy data): {accuracy:.2%}")

    with open('sample_model.pkl', 'wb') as f:
        pickle.dump(model, f)

    print("\n✅ sample_model.pkl created successfully.")
    print("\n⚠️  This is a DUMMY model trained on SYNTHETIC data.")
    print("   It is NOT suitable for real malware detection.")
    print("   See ml/feature_schema.md for training on real APK data.")

    # Test prediction
    test_malicious = np.array([[20, 10, 5, 5, 20, 1, 1, 1, 1, 5, 1, 5000, 15, 1, 75, 70, 80]])
    pred = model.predict(test_malicious)
    prob = model.predict_proba(test_malicious)[0]
    labels = ['SAFE', 'SUSPICIOUS', 'MALICIOUS']
    print(f"\nTest prediction (clearly malicious features):")
    print(f"  → {labels[pred[0]]} (confidence: {prob.max():.2%})")


if __name__ == '__main__':
    main()