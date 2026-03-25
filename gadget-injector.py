#!/usr/bin/env python3

"""
fridaInject.py
Full pipeline: Pull APK from device → Merge splits → Inject Frida Gadget → Zipalign → Sign
Usage: python fridaInject.py <package.name>
"""

import sys
import os
import re
import shutil
import platform
import subprocess
import zipfile
import xml.etree.ElementTree as ET

# ──────────────────────────────────────────────
# CONFIG — edit these or override via env vars
# ──────────────────────────────────────────────
OS = platform.system()  # Darwin, Linux, Windows

DEFAULT_JARS = {
    "Darwin": {
        "apkeditor":  os.path.expanduser("~/tools/APKEditor.jar"),
        "ubersigner": os.path.expanduser("~/tools/uber-apk-signer.jar"),
    },
    "Linux": {
        "apkeditor":  os.path.expanduser("~/tools/APKEditor.jar"),
        "ubersigner": os.path.expanduser("~/tools/uber-apk-signer.jar"),
    },
    "Windows": {
        "apkeditor":  r"C:\tools\mobile\APKEditor.jar",
        "ubersigner": r"C:\tools\mobile\uber-apk-signer.jar",
    },
}

FRIDA_GADGET_PATH = None  # resolved from CLI args

# Frida gadget ABI → path inside APK
GADGET_ABI_MAP = {
    "arm64-v8a":   "lib/arm64-v8a/libfrida-gadget.so",
    "armeabi-v7a": "lib/armeabi-v7a/libfrida-gadget.so",
    "x86":         "lib/x86/libfrida-gadget.so",
    "x86_64":      "lib/x86_64/libfrida-gadget.so",
}


# ──────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────
def log(emoji, msg):
    print(f"{emoji}  {msg}")

def die(msg):
    print(f"\n❌ {msg}")
    sys.exit(1)

def run(cmd, check=True, capture=True):
    result = subprocess.run(cmd, capture_output=capture, text=True, check=False)
    if check and result.returncode != 0:
        cmd_str = " ".join(str(c) for c in cmd)
        print(f"\n❌ Command failed: {cmd_str}")
        if result.stdout.strip():
            print(result.stdout)
        if result.stderr.strip():
            print(result.stderr)
        sys.exit(result.returncode)
    return result

def require_tool(name):
    if not shutil.which(name):
        die(f"'{name}' not found. Please install it and ensure it's in your PATH.")

def resolve_jar(env_var, default, label, url):
    path = os.environ.get(env_var, default)
    if not os.path.isfile(path):
        die(f"{label} not found at: {path}\nDownload from: {url}\nOr set {env_var}=/path/to/jar")
    return path


# ──────────────────────────────────────────────
# STEP 1 — Pull splits from device
# ──────────────────────────────────────────────
def pull_splits(package, splits_dir):
    log("⬇️ ", f"Pulling APK splits for '{package}'...")

    result = run(["adb", "shell", "pm", "path", package], check=False)
    if result.returncode != 0 or not result.stdout.strip():
        die(f"Package '{package}' not found on device.")

    paths = [
        line.strip().replace("\r", "")[len("package:"):]
        for line in result.stdout.splitlines()
        if line.strip().startswith("package:")
    ]

    if not paths:
        die("No APK paths returned by adb.")

    os.makedirs(splits_dir, exist_ok=True)
    for path in paths:
        log("  →", path)
        run(["adb", "pull", path, splits_dir])

    log("✅", f"Pulled {len(paths)} file(s) to {splits_dir}")
    return paths


# ──────────────────────────────────────────────
# STEP 2 — Merge splits
# ──────────────────────────────────────────────
def merge_splits(apkeditor_jar, splits_dir, merged_apk):
    apks = [f for f in os.listdir(splits_dir) if f.endswith(".apk")]

    if len(apks) == 1:
        # Only one APK — no need to merge, just copy it
        log("📋", "Single APK detected — skipping merge, copying directly...")
        shutil.copy2(os.path.join(splits_dir, apks[0]), merged_apk)
    else:
        log("🔀", f"Merging {len(apks)} splits with APKEditor...")
        run(["java", "-jar", apkeditor_jar, "m", "-i", splits_dir, "-o", merged_apk])

    if not os.path.isfile(merged_apk):
        die("Merge failed — merged.apk not found.")
    log("✅", f"Merged APK: {merged_apk}")


# ──────────────────────────────────────────────
# STEP 3 — Decode APK with apktool
# ──────────────────────────────────────────────
def decode_apk(merged_apk, decoded_dir):
    log("📂", "Decoding APK with apktool (smali only, skipping resources)...")
    if os.path.exists(decoded_dir):
        shutil.rmtree(decoded_dir)
    run(["apktool", "d", merged_apk, "-o", decoded_dir, "--no-res", "-f"])
    if not os.path.exists(decoded_dir):
        die("apktool decode failed.")
    log("✅", f"Decoded to: {decoded_dir}")


# ──────────────────────────────────────────────
# STEP 4 — Parse AndroidManifest to find entry point
# ──────────────────────────────────────────────
def find_entry_point(merged_apk):
    log("🔍", "Analyzing AndroidManifest.xml for entry point...")

    # Decode into a temp dir WITHOUT --no-res so apktool converts binary XML to text
    # We never rebuild from this dir so resource compile errors are irrelevant
    tmp_dir = merged_apk + "_manifest_tmp"
    try:
        if os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir)

        # check=False because apktool may fail on resources but still write the manifest
        run(["apktool", "d", merged_apk, "-o", tmp_dir, "--no-src", "-f"], check=False)

        manifest_path = os.path.join(tmp_dir, "AndroidManifest.xml")
        if not os.path.isfile(manifest_path):
            die("AndroidManifest.xml not found after decoding.")

        tree = ET.parse(manifest_path)
        root = tree.getroot()

        ns = "http://schemas.android.com/apk/res/android"
        package = root.get("package", "")

        for activity in root.iter("activity"):
            for intent_filter in activity.iter("intent-filter"):
                actions    = [a.get(f"{{{ns}}}name") for a in intent_filter.iter("action")]
                categories = [c.get(f"{{{ns}}}name") for c in intent_filter.iter("category")]

                if ("android.intent.action.MAIN" in actions and
                        "android.intent.category.LAUNCHER" in categories):

                    activity_name = activity.get(f"{{{ns}}}name", "")

                    if activity_name.startswith("."):
                        activity_name = package + activity_name
                    elif "." not in activity_name:
                        activity_name = package + "." + activity_name

                    log("✅", f"Entry point found: {activity_name}")
                    return activity_name

        die("Could not find MAIN/LAUNCHER activity in AndroidManifest.xml.")
    finally:
        if os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir)

def inject_frida(decoded_dir, activity_class):
    log("💉", f"Injecting Frida gadget into {activity_class}...")

    # Convert class name to smali path
    # e.g. fr.doctolib.www.MainActivity → smali/fr/doctolib/www/MainActivity.smali
    class_path = activity_class.replace(".", "/")

    # Search across smali, smali_classes2, smali_classes3 etc.
    smali_file = None
    for root_dir, dirs, files in os.walk(decoded_dir):
        candidate = os.path.join(root_dir, class_path + ".smali")
        if os.path.isfile(candidate):
            smali_file = candidate
            break

    if not smali_file:
        die(f"Smali file not found for {activity_class}\nLooked for: {class_path}.smali")

    log("  →", f"Found smali: {smali_file}")

    with open(smali_file, "r") as f:
        content = f.read()

    # Find onCreate(Landroid/os/Bundle;)V — the standard entry point
    # Fall back to <init> if onCreate is not present
    if ".method protected onCreate(Landroid/os/Bundle;)V" in content:
        method_sig = ".method protected onCreate(Landroid/os/Bundle;)V"
    elif ".method public onCreate(Landroid/os/Bundle;)V" in content:
        method_sig = ".method public onCreate(Landroid/os/Bundle;)V"
    else:
        log("⚠️ ", "onCreate not found, falling back to constructor <init>")
        method_sig = ".method public constructor <init>()V"

    # Find the method and its .locals line
    pattern = re.compile(
        rf"({re.escape(method_sig)}\n(\s+\.registers \d+\n)?(\s+\.locals )(\d+))",
        re.MULTILINE
    )

    match = pattern.search(content)
    if not match:
        die(f"Could not find .locals declaration in method: {method_sig}")

    locals_count = int(match.group(4))
    new_locals   = locals_count + 1  # need one extra register for v{n}
    register     = f"v{locals_count}"  # use the new register

    frida_snippet = (
        f"\n    # --- Frida Gadget ---\n"
        f"    const-string {register}, \"frida-gadget\"\n"
        f"    invoke-static {{{register}}}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n"
        f"    # --- End Frida Gadget ---\n"
    )

    # Replace .locals N with new count and append snippet right after
    old_locals_line = match.group(3) + match.group(4)
    new_locals_line = match.group(3) + str(new_locals)

    # Insert after the .locals line inside the matched method
    insert_after = match.group(0).replace(old_locals_line, new_locals_line)
    new_content  = content.replace(match.group(0), insert_after + frida_snippet, 1)

    with open(smali_file, "w") as f:
        f.write(new_content)

    log("✅", f"Frida gadget injected into {smali_file}")


# ──────────────────────────────────────────────
# STEP 6 — Copy Frida gadget .so into lib/
# ──────────────────────────────────────────────
def copy_gadget(decoded_dir, gadget_path):
    log("📦", "Copying Frida gadget .so into lib directories...")

    if not os.path.isfile(gadget_path):
        die(
            f"frida-gadget .so not found at: {gadget_path}\n"
            f"Download from: https://github.com/frida/frida/releases\n"
            f"Pass it via: --gadget /path/to/libfrida-gadget.so"
        )

    copied = 0
    lib_base = os.path.join(decoded_dir, "lib")

    if os.path.isdir(lib_base):
        for abi in os.listdir(lib_base):
            if abi in GADGET_ABI_MAP:
                dest = os.path.join(lib_base, abi, "libfrida-gadget.so")
                shutil.copy2(gadget_path, dest)
                log("  →", f"Copied to lib/{abi}/")
                copied += 1

    if copied == 0:
        # No existing lib dirs — create arm64-v8a as default
        log("⚠️ ", "No lib dirs found, creating lib/arm64-v8a/")
        dest_dir = os.path.join(decoded_dir, "lib", "arm64-v8a")
        os.makedirs(dest_dir, exist_ok=True)
        shutil.copy2(gadget_path, os.path.join(dest_dir, "libfrida-gadget.so"))
        log("  →", "Copied to lib/arm64-v8a/")

    log("✅", "Gadget .so copied successfully")


# ──────────────────────────────────────────────
# STEP 7 — Rebuild APK with apktool
# ──────────────────────────────────────────────
def rebuild_apk(decoded_dir, injected_apk):
    log("🔨", "Rebuilding APK with apktool...")
    run(["apktool", "b", decoded_dir, "-o", injected_apk, "-f"])
    if not os.path.isfile(injected_apk):
        die("apktool rebuild failed — injected.apk not found.")
    log("✅", f"Rebuilt APK: {injected_apk}")


# ──────────────────────────────────────────────
# STEP 8 — Zipalign
# ──────────────────────────────────────────────
def zipalign(injected_apk, aligned_apk):
    log("📐", "Zipaligning...")
    require_tool("zipalign")
    if os.path.isfile(aligned_apk):
        os.remove(aligned_apk)
    run(["zipalign", "-p", "4", injected_apk, aligned_apk])
    if not os.path.isfile(aligned_apk):
        die("zipalign failed.")
    log("✅", f"Aligned APK: {aligned_apk}")


# ──────────────────────────────────────────────
# STEP 9 — Sign
# ──────────────────────────────────────────────
def sign_apk(ubersigner_jar, aligned_apk, signed_dir):
    log("✍️ ", "Signing APK...")
    run(["java", "-jar", ubersigner_jar, "-a", aligned_apk, "--allowResign", "-o", signed_dir])
    log("✅", f"Signed APK saved to: {signed_dir}")


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────
def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Pull APK from device, inject Frida gadget, zipalign and sign.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("package",
        help="Android package name. Example: fr.doctolib.www")
    parser.add_argument("--gadget", required=True,
        help="Path to the Frida gadget .so file. Example: ~/tools/frida/libfrida-gadget.so")

    args = parser.parse_args()
    package = args.package

    global FRIDA_GADGET_PATH
    FRIDA_GADGET_PATH = os.path.expanduser(args.gadget)

    if OS not in DEFAULT_JARS:
        die(f"Unsupported OS: {OS}")

    # Resolve JARs
    apkeditor_jar  = resolve_jar("APKEDITOR_JAR",  DEFAULT_JARS[OS]["apkeditor"],
                                 "APKEditor.jar",   "https://github.com/REAndroid/APKEditor/releases")
    ubersigner_jar = resolve_jar("UBERSIGNER_JAR", DEFAULT_JARS[OS]["ubersigner"],
                                 "uber-apk-signer.jar", "https://github.com/patrickfav/uber-apk-signer/releases")

    # Check tools
    for tool in ["adb", "java", "apktool", "zipalign"]:
        require_tool(tool)

    result = run(["adb", "get-state"], check=False)
    if result.returncode != 0:
        die("No Android device detected. Connect a device with USB debugging enabled.")

    # Paths
    work_dir     = os.path.join(os.getcwd(), f"{package}_frida")
    splits_dir   = os.path.join(work_dir, "splits")
    merged_apk   = os.path.join(work_dir, "merged.apk")
    decoded_dir  = os.path.join(work_dir, "decoded")
    injected_apk = os.path.join(work_dir, "injected.apk")
    aligned_apk  = os.path.join(work_dir, "injectedAlign.apk")
    signed_dir   = os.path.join(work_dir, "signed")

    os.makedirs(work_dir, exist_ok=True)
    os.makedirs(signed_dir, exist_ok=True)

    print(f"\n📦 Package : {package}")
    print(f"💻 OS      : {OS}")
    print(f"📁 Output  : {work_dir}\n")

    pull_splits(package, splits_dir)
    merge_splits(apkeditor_jar, splits_dir, merged_apk)
    decode_apk(merged_apk, decoded_dir)
    activity = find_entry_point(merged_apk)
    inject_frida(decoded_dir, activity)
    copy_gadget(decoded_dir, FRIDA_GADGET_PATH)
    rebuild_apk(decoded_dir, injected_apk)
    zipalign(injected_apk, aligned_apk)
    sign_apk(ubersigner_jar, aligned_apk, signed_dir)

    print(f"\n🎉 Done!")
    print(f"   Entry point injected : {activity}")
    print(f"   Signed APK           : {signed_dir}/")

if __name__ == "__main__":
    main()
