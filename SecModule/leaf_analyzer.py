import lief
import os
from ollama import chat

from SecModule import common_utils


def analyze_file(file_path):
    try:
        binary = lief.parse(file_path)
        features = {
            "file": file_path,
            "entropy": max([s.entropy for s in binary.sections]) if binary.sections else 0,
            "dll_count": len(binary.libraries) if binary.libraries else 0,
            "import_count": len(binary.imports) if binary.has_imports else 0
        }
        return features
    except Exception as e:
        return {"file": file_path, "error": str(e)}




def ask_to_modell(features):
    prompt = f"Analizza queste caratteristiche di file binari e indica se potrebbero essere malware:\n{features}"
    response = chat(model="llama3", messages=[{"role": "user", "content": prompt}])
    return response['message']['content']

def run_scan(file_path):
    risultati = []
    if file_path.endswith((".exe", ".dll")):
        risultati.append(analyze_file(file_path))
        # Analisi AI
        for f in risultati:
            if "error" not in f:
                print(f"\n📁 File: {f['file']}")
                print(ask_to_modell(f))

def main():
    # Estrai e analizza
    common_utils.zip_extraction("malware_sample.zip", "estratti/")
    risultati = []
    for root, _, files in os.walk("estratti/"):
        for f in files:
            if f.endswith((".exe", ".dll")):
                path = os.path.join(root, f)
                risultati.append(analyze_file(path))
    # Analisi AI
    for f in risultati:
        if "error" not in f:
            print(f"\n📁 File: {f['file']}")
            print(ask_to_modell(f))

if __name__ == "__main__":
    main()