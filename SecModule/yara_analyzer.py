import traceback

import yara
import os


yara_result=False

# ✅ Scansione YARA
def scan_yara(file_path, rules_path='../yara_def/malware_index.yar'):
    rules = yara.compile(filepath=rules_path)
    matches = rules.match(file_path)
    return matches

def batch_scan(directory='samples'):
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        print(f"🔍 Analisi in corso su {filename}")
        # Esegui le funzioni scan_yara, scan_clamav, etc.

def analyze_logs(log_file='logs/scan_log.txt'):
    with open(log_file, 'r') as f:
        lines = f.readlines()

    threats = [line for line in lines if 'quarantena' in line]
    clean = [line for line in lines if 'pulito' in line]

    print(f"🧪 Totale minacce: {len(threats)}")
    print(f"✅ File puliti: {len(clean)}")


def run_scan(file_path, rules_path=None):
    print(f"[YARA] 🔍  version: {yara.__version__}")
    print(f"\n[YARA]🧪 Scansione file:{file_path}")
   # YARA scan
    try:
        matches = scan_yara(file_path,rules_path)
        if matches:
            print(f"[YARA] 💀 Minaccia rilevata:{matches}\n")
            yara_result=True
        else:
            print(f"[YARA] ✅ Nessuna minaccia rilevata.\n")
            yara_result = False
    except Exception as e:
        print(f"[YARA] Errore: {e}\n")
        tb = traceback.extract_tb(e.__traceback__)
        print("[YARA] 📌 Stack trace completo:")
        for i, frame in enumerate(tb):
            print(f"[YARA]   [{i}] File: {frame.filename}")
            print(f"[YARA]         Funzione: {frame.name}")
            print(f"[YARA]         Riga: {frame.lineno}")
            print(f"[YARA]         Codice: {frame.line}")

def is_critical():
    return yara_result


def main():
    # Estrai e analizza
    run_scan("../samples/binary/Civil_War.282.zip")


if __name__ == "__main__":
    main()



