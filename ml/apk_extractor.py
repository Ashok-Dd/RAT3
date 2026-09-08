"""
apk_extractor.py
─────────────────────────────────────────────────────────────
Extracts the 241 binary features used by the TUANDROMD model
from a raw APK file (zip-based format).

Features extracted:
  • Android permissions  (from AndroidManifest.xml)
  • Dangerous API calls  (from DEX bytecode via strings scan)
  • activityCalled flag  (any activity declaration present)
─────────────────────────────────────────────────────────────
FIX: Robust feature_list.json loading with auto-generation
     fallback so the app never crashes on a missing/empty file.
"""

import zipfile
import re
import json
import os
import sys
from pathlib import Path

# ─────────────────────────────────────────────────────────────
# Hardcoded fallback feature list (all 241 TUANDROMD features).
# Used automatically if feature_list.json is missing or empty.
# ─────────────────────────────────────────────────────────────
_FALLBACK_FEATURES = [
    "ACCESS_ALL_DOWNLOADS","ACCESS_CACHE_FILESYSTEM","ACCESS_CHECKIN_PROPERTIES",
    "ACCESS_COARSE_LOCATION","ACCESS_COARSE_UPDATES","ACCESS_FINE_LOCATION",
    "ACCESS_LOCATION_EXTRA_COMMANDS","ACCESS_MOCK_LOCATION","ACCESS_MTK_MMHW",
    "ACCESS_NETWORK_STATE","ACCESS_PROVIDER","ACCESS_SERVICE","ACCESS_SHARED_DATA",
    "ACCESS_SUPERUSER","ACCESS_SURFACE_FLINGER","ACCESS_WIFI_STATE","activityCalled",
    "ACTIVITY_RECOGNITION","ACCOUNT_MANAGER","ADD_VOICEMAIL","ANT","ANT_ADMIN",
    "AUTHENTICATE_ACCOUNTS","AUTORUN_MANAGER_LICENSE_MANAGER",
    "AUTORUN_MANAGER_LICENSE_SERVICE(.autorun)","BATTERY_STATS","BILLING",
    "BIND_ACCESSIBILITY_SERVICE","BIND_APPWIDGET","BIND_CARRIER_MESSAGING_SERVICE",
    "BIND_DEVICE_ADMIN","BIND_DREAM_SERVICE","BIND_GET_INSTALL_REFERRER_SERVICE",
    "BIND_INPUT_METHOD","BIND_NFC_SERVICE","BIND_goodwareTIFICATION_LISTENER_SERVICE",
    "BIND_PRINT_SERVICE","BIND_REMOTEVIEWS","BIND_TEXT_SERVICE","BIND_TV_INPUT",
    "BIND_VOICE_INTERACTION","BIND_VPN_SERVICE","BIND_WALLPAPER","BLUETOOTH",
    "BLUETOOTH_ADMIN","BLUETOOTH_PRIVILEGED","BODY_SENSORS","BRICK",
    "BROADCAST_PACKAGE_REMOVED","BROADCAST_SMS","BROADCAST_STICKY","BROADCAST_WAP_PUSH",
    "C2D_MESSAGE","CALL_PHONE","CALL_PRIVILEGED","CAMERA","CAPTURE_AUDIO_OUTPUT",
    "CAPTURE_SECURE_VIDEO_OUTPUT","CAPTURE_VIDEO_OUTPUT","CHANGE_COMPONENT_ENABLED_STATE",
    "CHANGE_CONFIGURATION","CHANGE_DISPLAY_MODE","CHANGE_NETWORK_STATE",
    "CHANGE_WIFI_MULTICAST_STATE","CHANGE_WIFI_STATE","CHECK_LICENSE","CLEAR_APP_CACHE",
    "CLEAR_APP_USER_DATA","CONTROL_LOCATION_UPDATES","DATABASE_INTERFACE_SERVICE",
    "DELETE_CACHE_FILES","DELETE_PACKAGES","DEVICE_POWER","DIAGgoodwareSTIC",
    "DISABLE_KEYGUARD","DOWNLOAD_SERVICE","DOWNLOAD_WITHOUT_goodwareTIFICATION","DUMP",
    "EXPAND_STATUS_BAR","EXTENSION_PERMISSION","FACTORY_TEST","FLASHLIGHT","FORCE_BACK",
    "FULLSCREEN.FULL","GET_ACCOUNTS","GET_PACKAGE_SIZE","GET_TASKS",
    "GET_TOP_ACTIVITY_INFO","GLOBAL_SEARCH","GOOGLE_AUTH","GOOGLE_PHOTOS",
    "HARDWARE_TEST","INJECT_EVENTS","INSTALL_LOCATION_PROVIDER","INSTALL_PACKAGES",
    "INSTALL_SHORTCUT","INTERACT_ACROSS_USERS","INTERNAL_SYSTEM_WINDOW","INTERNET",
    "JPUSH_MESSAGE","KILL_BACKGROUND_PROCESSES","LOCATION_HARDWARE","MANAGE_ACCOUNTS",
    "MANAGE_APP_TOKENS","MANAGE_DOCUMENTS","MAPS_RECEIVE","MASTER_CLEAR","MEDIA_BUTTON",
    "MEDIA_CONTENT_CONTROL","MESSAGE","MODIFY_AUDIO_SETTINGS","MODIFY_PHONE_STATE",
    "MOUNT_FORMAT_FILESYSTEMS","MOUNT_UNMOUNT_FILESYSTEMS","NFC","PERSISTENT_ACTIVITY",
    "PERMISSION","PERMISSION_RUN_TASKS","PLUGIN","PROCESS_OUTGOING_CALLS","READ",
    "READ_ATTACHMENT","READ_AVESTTINGS","READ_CALENDAR","READ_CALL_LOG","READ_CONTACTS",
    "READ_CONTENT_PROVIDER","READ_DATA","READ_DATABASES","READ_EXTERNAL_STORAGE",
    "READ_FRAME_BUFFER","READ_GMAIL","READ_GSERVICES","READ_HISTORY_BOOKMARKS",
    "READ_INPUT_STATE","READ_LOGS","READ_MESSAGES","READ_OWNER_DATA","READ_PHONE_STATE",
    "READ_PROFILE","READ_SETTINGS","READ_SMS","READ_SOCIAL_STREAM","READ_SYNC_SETTINGS",
    "READ_SYNC_STATS","READ_USER_DICTIONARY","READ_VOICEMAIL","REBOOT","RECEIVE",
    "RECEIVE_BOOT_COMPLETED","RECEIVE_MMS","RECEIVE_SIGNED_DATA_RESULT","RECEIVE_SMS",
    "RECEIVE_USER_PRESENT","RECEIVE_WAP_PUSH","RECORD_AUDIO","REORDER_TASKS","RESPOND",
    "RESTART_PACKAGES","REQUEST","SDCARD_WRITE","SEND","SEND_RESPOND_VIA_MESSAGE",
    "SEND_SMS","SET_ACTIVITY_WATCHER","SET_ALARM","SET_ALWAYS_FINISH",
    "SET_ANIMATION_SCALE","SET_DEBUG_APP","SET_ORIENTATION","SET_POINTER_SPEED",
    "SET_PREFERRED_APPLICATIONS","SET_PROCESS_LIMIT","SET_TIME","SET_TIME_ZONE",
    "SET_WALLPAPER","SET_WALLPAPER_HINTS","SIGNAL_PERSISTENT_PROCESSES","STATUS_BAR",
    "STORAGE","SUBSCRIBED_FEEDS_READ","SUBSCRIBED_FEEDS_WRITE","SYSTEM_ALERT_WINDOW",
    "TRANSMIT_IR","UNINSTALL_SHORTCUT","UPDATE_DEVICE_STATS","USES_POLICY_FORCE_LOCK",
    "USE_CREDENTIALS","USE_FINGERPRINT","USE_SIP","VIBRATE","WAKE_LOCK","WRITE",
    "WRITE_APN_SETTINGS","WRITE_AVSETTING","WRITE_CALENDAR","WRITE_CALL_LOG",
    "WRITE_CONTACTS","WRITE_DATA","WRITE_DATABASES","WRITE_EXTERNAL_STORAGE",
    "WRITE_GSERVICES","WRITE_HISTORY_BOOKMARKS","WRITE_INTERNAL_STORAGE",
    "WRITE_MEDIA_STORAGE","WRITE_OWNER_DATA","WRITE_PROFILE","WRITE_SECURE_SETTINGS",
    "WRITE_SETTINGS","WRITE_SMS","WRITE_SOCIAL_STREAM","WRITE_SYNC_SETTINGS",
    "WRITE_USER_DICTIONARY","WRITE_VOICEMAIL",
    "LOCATION_HARDWARE",
    "Ljava/lang/reflect/Method;->invoke",
    "Ljavax/crypto/Cipher;->doFinal",
    "Ljava/lang/Runtime;->exec",
    "Ljava/lang/System;->load",
    "Ldalvik/system/DexClassLoader;->loadClass",
    "Ljava/lang/System;->loadLibrary",
    "Ljava/net/URL;->openConnection",
    "Landroid/hardware/Camera;->open",
    "Landroid/hardware/Camera;->takePicture",
    "Landroid/telephony/SmsManager;->sendMultipartTextMessage",
    "Landroid/telephony/SmsManager;->sendTextMessage",
    "Landroid/media/AudioRecord;->startRecording",
    "Landroid/telephony/TelephonyManager;->getCellLocation",
    "Lcom/google/android/gms/location/LocationClient;->getLastLocation",
    "Landroid/location/LocationManager;->getLastKgoodwarewnLocation",
    "Landroid/telephony/TelephonyManager;->getDeviceId",
    "Landroid/content/pm/PackageManager;->getInstalledApplications",
    "Landroid/content/pm/PackageManager;->getInstalledPackages",
    "Landroid/telephony/TelephonyManager;->getLine1Number",
    "Landroid/telephony/TelephonyManager;->getNetworkOperator",
    "Landroid/telephony/TelephonyManager;->getNetworkOperatorName",
    "Landroid/telephony/TelephonyManager;->getNetworkCountryIso",
    "Landroid/telephony/TelephonyManager;->getSimOperator",
    "Landroid/telephony/TelephonyManager;->getSimOperatorName",
    "Landroid/telephony/TelephonyManager;->getSimCountryIso",
    "Landroid/telephony/TelephonyManager;->getSimSerialNumber",
    "Lorg/apache/http/impl/client/DefaultHttpClient;->execute",
]


_HERE        = Path(__file__).parent
_JSON_PATH   = _HERE / "models" / "feature_list.json"


def _load_feature_list() -> list:
    """
    Load feature list with three-tier fallback:
      1. Read models/feature_list.json  (normal path)
      2. Auto-generate from TUANDROMD.csv if json is missing/empty
      3. Use hardcoded _FALLBACK_FEATURES as last resort
    """
    if _JSON_PATH.exists():
        try:
            content = _JSON_PATH.read_text(encoding="utf-8").strip()
            if content:                            # non-empty file
                features = json.loads(content)
                if isinstance(features, list) and len(features) > 0:
                    print(f"[apk_extractor] Loaded {len(features)} features from {_JSON_PATH}")
                    return features
            print(f"[apk_extractor] Warning: {_JSON_PATH} is empty.")
        except (json.JSONDecodeError, OSError) as e:
            print(f"[apk_extractor] Warning: could not parse {_JSON_PATH}: {e}")
    else:
        print(f"[apk_extractor] Warning: {_JSON_PATH} not found.")

    csv_candidates = [
        _HERE / "TUANDROMD.csv",
        _HERE.parent / "TUANDROMD.csv",
        Path("TUANDROMD.csv"),
    ]
    for csv_path in csv_candidates:
        if csv_path.exists():
            try:
                import pandas as pd
                df      = pd.read_csv(csv_path, nrows=0)   # header only
                columns = [c for c in df.columns if c != "Label"]
                if columns:
                    print(f"[apk_extractor] Auto-generated {len(columns)} features from {csv_path}")
                    # Save for next time
                    _JSON_PATH.parent.mkdir(parents=True, exist_ok=True)
                    _JSON_PATH.write_text(
                        json.dumps(columns, indent=2), encoding="utf-8"
                    )
                    return columns
            except Exception as e:
                print(f"[apk_extractor] Warning: could not read {csv_path}: {e}")

    print(f"[apk_extractor] Using hardcoded fallback feature list ({len(_FALLBACK_FEATURES)} features).")
    # Save it for next time
    try:
        _JSON_PATH.parent.mkdir(parents=True, exist_ok=True)
        _JSON_PATH.write_text(
            json.dumps(_FALLBACK_FEATURES, indent=2), encoding="utf-8"
        )
    except OSError:
        pass
    return list(_FALLBACK_FEATURES)


def generate_feature_list(csv_path: str, save: bool = True) -> list:
    """
    Public helper: (re-)generate feature_list.json from a CSV file.

    Usage:
        from apk_extractor import generate_feature_list
        generate_feature_list("TUANDROMD.csv")

    Parameters
    ----------
    csv_path : str  – path to TUANDROMD.csv (or any CSV with same columns)
    save     : bool – if True, overwrites models/feature_list.json

    Returns
    -------
    list of feature name strings
    """
    import pandas as pd
    df       = pd.read_csv(csv_path, nrows=0)
    features = [c for c in df.columns if c != "Label"]
    if not features:
        raise ValueError(f"No feature columns found in {csv_path}")
    if save:
        _JSON_PATH.parent.mkdir(parents=True, exist_ok=True)
        _JSON_PATH.write_text(json.dumps(features, indent=2), encoding="utf-8")
        print(f"[apk_extractor] Saved {len(features)} features → {_JSON_PATH}")
    return features


# Initialise at import time
FEATURE_LIST        = _load_feature_list()
PERMISSION_FEATURES = [f for f in FEATURE_LIST
                       if not f.startswith("L") and f != "activityCalled"]
API_FEATURES        = [f for f in FEATURE_LIST if f.startswith("L")]



def _read_manifest_bytes(apk_path: str) -> bytes:
    """Return the raw (binary XML) bytes of AndroidManifest.xml."""
    with zipfile.ZipFile(apk_path, "r") as z:
        return z.read("AndroidManifest.xml")


def _decode_binary_xml(data: bytes) -> str:
    """
    Lightweight binary-XML → plain-text decoder.
    Extracts printable ASCII runs; good enough to find
    permission names and activity declarations.
    """
    text = data.decode("latin-1", errors="replace")
    raw_strings = re.findall(r"[\x20-\x7e]{4,}", text)
    return "\n".join(raw_strings)


def _extract_permissions_from_manifest(manifest_text: str) -> set:
    """Return set of bare permission names found in the manifest text."""
    found = set()

    # Match android.permission.XXX  or  android.Manifest.permission.XXX
    for m in re.finditer(
        r"(?:android\.permission\.|android\.Manifest\.permission\.|"
        r"com\.\w+\.permission\.)([A-Z_0-9]+)",
        manifest_text,
        re.IGNORECASE,
    ):
        found.add(m.group(1).upper())

    # Also scan for bare names that appear verbatim in the binary XML
    for perm in PERMISSION_FEATURES:
        if re.search(r"\b" + re.escape(perm) + r"\b", manifest_text, re.IGNORECASE):
            found.add(perm.upper())

    return found


def _extract_strings_from_dex(apk_path: str) -> str:
    """
    Read all .dex files inside the APK and return their printable strings.
    Sufficient for API-call pattern matching.
    """
    all_strings = []
    with zipfile.ZipFile(apk_path, "r") as z:
        dex_files = [n for n in z.namelist() if re.match(r"classes\d*\.dex$", n)]
        for dex_name in dex_files:
            raw = z.read(dex_name)
            printable = re.findall(rb"[\x20-\x7e]{5,}", raw)
            all_strings.extend(s.decode("ascii", errors="replace") for s in printable)
    return "\n".join(all_strings)


def _has_activity(manifest_text: str) -> bool:
    return bool(re.search(r"\bactivity\b", manifest_text, re.IGNORECASE))


# ─────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────

def extract_features(apk_path: str) -> dict:
    """
    Given a path to an APK file, return a dict with:
      'features'  – {feature_name: 0 or 1} for all 241 features
      'metadata'  – extraction details and any warnings
    """
    features = {f: 0 for f in FEATURE_LIST}
    metadata = {
        "_permissions_found":  [],
        "_apis_found":         [],
        "_total_permissions":  [],
        "_apk_size_kb":        round(os.path.getsize(apk_path) / 1024, 1),
        "_dex_count":          0,
        "_error":              None,
    }

    try:
        manifest_bytes = _read_manifest_bytes(apk_path)
        manifest_text  = _decode_binary_xml(manifest_bytes)

        found_perms = _extract_permissions_from_manifest(manifest_text)
        metadata["_total_permissions"] = sorted(found_perms)

        for perm in PERMISSION_FEATURES:
            if perm.upper() in found_perms:
                features[perm] = 1
                metadata["_permissions_found"].append(perm)

        # activityCalled flag
        if _has_activity(manifest_text):
            features["activityCalled"] = 1

        # ── 2. DEX → API calls ───────────────────────────
        with zipfile.ZipFile(apk_path, "r") as z:
            dex_files = [n for n in z.namelist() if re.match(r"classes\d*\.dex$", n)]
        metadata["_dex_count"] = len(dex_files)

        dex_strings = _extract_strings_from_dex(apk_path)

        for api in API_FEATURES:
            pattern = re.escape(api).replace(r"\-\>", r"[\->]+")
            if re.search(pattern, dex_strings):
                features[api] = 1
                metadata["_apis_found"].append(api)

    except zipfile.BadZipFile:
        metadata["_error"] = "Not a valid APK / ZIP file."
    except KeyError as e:
        metadata["_error"] = f"Missing entry in APK: {e}"
    except Exception as e:
        metadata["_error"] = f"Extraction error: {e}"

    return {"features": features, "metadata": metadata}


def feature_vector(apk_path: str):
    """
    Returns (vector, metadata) where vector is a list of 241 floats
    in the canonical FEATURE_LIST order, ready for model.predict().
    """
    result   = extract_features(apk_path)
    features = result["features"]
    vector   = [float(features[f]) for f in FEATURE_LIST]
    return vector, result["metadata"]


if __name__ == "__main__":
    if len(sys.argv) == 2:
        csv = sys.argv[1]
        feats = generate_feature_list(csv, save=True)
        print(f"Done. {len(feats)} features written to {_JSON_PATH}")
    else:
        print("Usage:  python apk_extractor.py TUANDROMD.csv")
        print(f"Current feature_list.json: {_JSON_PATH}")
        print(f"Features loaded at runtime: {len(FEATURE_LIST)}")