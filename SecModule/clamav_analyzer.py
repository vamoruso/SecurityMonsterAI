import traceback

import pyclamd
import os


clamav_result=False

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
    print(f"[ClamAV] 🐱  version: {pyclamd.__version__}")
    print(f"\n[ClamAV] 🧪 Scansione file:{file_path}")
    absolute_path=os.path.abspath(file_path)
    #print(absolute_path)
    # ClamAV scan
    try:
        cd = pyclamd.ClamdNetworkSocket(host='127.0.0.1', port=3310)
        result = cd.scan_file(absolute_path)
        if result:
            print( f"[ClamAV] 💀 Minaccia rilevata:{result}\n")
            clamav_result=True
        else:
            print( "[ClamAV] ✅ Nessuna minaccia rilevata.\n")
            clamav_result = False
    except Exception as e:
        print( f"[ClamAV] Errore: {e}\n")
        tb = traceback.extract_tb(e.__traceback__)
        print("[YARA] 📌 Stack trace completo:")
        for i, frame in enumerate(tb):
            print(f"[ClamAV]   [{i}] File: {frame.filename}")
            print(f"[ClamAV]         Funzione: {frame.name}")
            print(f"[ClamAV]         Riga: {frame.lineno}")
            print(f"[ClamAV]         Codice: {frame.line}")

def is_critical():
    return clamav_result





def main():
    # Estrai e analizza
    run_scan("../samples/binary/Civil_War.282.zip")

if __name__ == "__main__":
    main()
