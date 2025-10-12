import yara
import os


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


def run_scan(file_path):
    print(f"🧪 Scansione file:\n{file_path}\n\n")
   # YARA scan
    try:
        matches = scan_yara(file_path)
        if matches:
            print(f"[YARA] Minaccia rilevata:\n{matches}\n")
        else:
            print(f"[YARA] Nessuna minaccia rilevata.\n")
    except Exception as e:
        print(f"[YARA] Errore: {e}\n")

clamav_result=False

def main():
    # Estrai e analizza
    run_scan("../samples/test.js")


if __name__ == "__main__":
    main()



