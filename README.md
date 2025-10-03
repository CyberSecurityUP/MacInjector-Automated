# MacInjector-Automated
MacInjector is a tool that lists macOS applications, checks code-signing vulnerabilities, and injects a dynamic library (dylib) into a vulnerable application.

## Created
Joas A Santos

## Features

- Lists all installed applications in the `/Applications` directory.
- Checks the code-signing integrity of a selected application.
- Compiles and injects a dynamic library (dylib) into the selected application.

## Requirements

- macOS
- Xcode Command Line Tools (to compile the C code)
- Python 3.6+

## How to Use

1. Clone the repository:
    ```bash
    git clone https://github.com/CyberSecurityUP/MacInjector.git
    cd MacInjector
    ```

2. Run the Python script:
    ```bash
    python3 mac_injector.py
    ```

3. The script will list all applications in `/Applications`. Select the number of the application you want to check and inject the dylib into.

## Technical Details

- **list_applications()**: Lists all applications in the `/Applications` directory.
- **check_vulnerability(app)**: Checks the code-signing integrity of the selected application.
- **compile_dylib()**: Compiles a C code that will be injected as a dylib.
- **inject_dylib(app)**: Injects the dylib into the selected application.

## Warning

This code is for educational and testing purposes only. Use it responsibly and only in controlled environments with proper permission. Code injection can cause damage or unexpected behavior in applications and systems.

## Contributions

Contributions are welcome! Feel free to open issues or submit pull requests.

## License

This project is licensed under the [MIT License](LICENSE).
