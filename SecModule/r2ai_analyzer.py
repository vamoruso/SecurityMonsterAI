#!/usr/bin/env python3
"""
analyze_with_r2ai.py — Windows 11 Compatible
Analyzes a binary file using radare2 + r2ai plugin via r2pipe.
"""

import sys
import os
import subprocess
import shutil
import r2pipe


def check_radare2_installed():
    """Check if radare2 is available in PATH."""
    if not shutil.which("r2"):
        raise EnvironmentError(
            "❌ radare2 not found. Install via Scoop: 'scoop install radare2'"
        )


def check_r2ai_installed():
    """Check if r2ai plugin is installed."""
    try:
        result = subprocess.run(
            ["r2", "-c", "r2ai -h", "-q"], capture_output=True, text=True
        )
        if "r2ai" not in result.stdout and "r2ai" not in result.stderr:
            raise EnvironmentError(
                "❌ r2ai plugin not found. Install with: 'r2pm -ci r2ai'"
            )
    except Exception as e:
        raise EnvironmentError(f"❌ Failed to check r2ai: {e}")


def ensure_model_downloaded():
    """Ensure at least one model is downloaded."""
    model_dir = os.path.expanduser("~/.r2ai/models")
    if not os.path.exists(model_dir) or not os.listdir(model_dir):
        print("⚠️ No models found in ~/.r2ai/models")
        print("👉 Download one manually, e.g.:")
        print("   mkdir %USERPROFILE%\\.r2ai\\models")
        print("   cd %USERPROFILE%\\.r2ai\\models")
        print("   curl -L -o ggml-model-q4_0.gguf https://huggingface.co/ggml-org/ggml/resolve/main/tinyllama-1.1b/ggml-model-q4_0.gguf")
        print("Or visit: https://github.com/radareorg/r2ai#models")
        return False
    return True


def analyze_file_with_r2ai(file_path, model_name=None, query="Explain the main function."):
    """
    Analyze a file using radare2 + r2ai plugin.

    :param file_path: Path to the binary file to analyze
    :param model_name: Optional — specify model (e.g., "tinyllama"), else uses default
    :param query: The AI prompt to send after analysis
    :return: AI response as string
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"❌ File not found: {file_path}")

    print(f"[+] Opening file: {file_path}")
    print(f"[+] Using AI query: '{query}'")

    # Open radare2 in command mode
    # Use flags=['-2'] to avoid ANSI/terminal color issues on Windows
    r2 = r2pipe.open(file_path, flags=['-2'])

    try:
        # Initialize analysis
        print("[+] Analyzing binary with 'aaa'...")
        r2.cmd("aaa")

        # Ensure r2ai is loaded
        print("[+] Loading r2ai plugin...")
        load_result = r2.cmd("r2ai")
        if "Usage" not in load_result and "Error" in load_result:
            raise RuntimeError(f"Failed to load r2ai: {load_result}")

        # Set model if specified
        if model_name:
            print(f"[+] Setting AI model: {model_name}")
            model_result = r2.cmd(f"r2ai -m {model_name}")
            if "Error" in model_result:
                print(f"⚠️ Model '{model_name}' may not be available. Using default.")

        # Send query to r2ai
        print("[+] Querying AI (this may take 10-60 seconds depending on model)...")
        ai_response = r2.cmd(f"r2ai {query}")

        if not ai_response.strip():
            ai_response = "⚠️ No response from r2ai. Model may be loading or query failed."

        return ai_response

    except Exception as e:
        raise RuntimeError(f"❌ Error during analysis: {str(e)}")

    finally:
        r2.quit()

def run_scan(file_path):
    run_scan(file_path,None, "Explain the main function.")

def run_scan(file_path,model_name):
    run_scan(file_path,model_name, "Explain the main function.")


def run_scan(file_path,model_name, query):
    check_radare2_installed()
    check_r2ai_installed()
    if not ensure_model_downloaded():
        sys.exit(1)
    try:
        result = analyze_file_with_r2ai(file_path, model_name, query)
        print("\n" + "=" * 70)
        print("🤖 r2ai RESPONSE:")
        print("=" * 70)
        print(result.strip())
        print("=" * 70)

    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)

def main():
    check_radare2_installed()
    #check_r2ai_installed()
    '''if not ensure_model_downloaded():
        sys.exit(1)
    '''

    if len(sys.argv) < 2:
        print("Usage: python r2aiAnalyzer.py <file_path> [model_name] [query]")
        print("Example: python r2aiAnalyzer.py C:\\Windows\\System32\\notepad.exe")
        sys.exit(1)

    file_path = sys.argv[1]
    model_name = sys.argv[2] if len(sys.argv) > 2 else None
    query = sys.argv[3] if len(sys.argv) > 3 else "Explain the main function."

    try:
        result = analyze_file_with_r2ai(file_path, model_name, query)
        print("\n" + "="*70)
        print("🤖 r2ai RESPONSE:")
        print("="*70)
        print(result.strip())
        print("="*70)

    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()