# Prima installa pyfiglet con il comando:
# pip install pyfiglet
import os
import time
from pathlib import Path

import pyfiglet
from tqdm import tqdm

from SecModule import source_code_analyzer, log_analyzer_ollama, leaf_analyzer, yara_analyzer,clamav_analyzer, r2ai_analyzer
from SecModule.common_utils import is_programming_file, is_log_file, is_executable_file


def esegui_comando(comando):
    if comando == "help":
        print("Comandi disponibili: help, scan, exit")
    elif comando.startswith("scan"):
        # Estrae il path dopo "scan"
        parti = comando.split(" ", 1)
        if len(parti) > 1:
            path = parti[1].strip()
            if path:  # Verifica che il path non sia vuoto
                print(f"Scansionando: {path}")
                run_scan(path)
                # Qui puoi aggiungere la logica di scansione effettiva
                # es: risultato = scanner.scan(path)
                #     print(risultato)
            else:
                print("Errore: specifica un file o percorso da scansionare")
        else:
            print("Errore: uso corretto -> scan <file/path name>")
            path = input("Inserisci il file/path da scansionare: ").strip()
            if path:
                print(f"Scansionando: {path}")
                # Qui puoi aggiungere la logica di scansione effettiva
                run_scan(path)
            else:
                print("Nessun path specificato")
    elif comando == "exit":
        return False  # Segnala di uscire
    else:
        print(f"Comando sconosciuto: {comando}")
    return True  # Continua il loop


def run_scan(absolute_file_path):
    file_path = Path(absolute_file_path)
    # Check if path exists
    if file_path.exists():
        if file_path.is_file():
            # Custom description and unit
            for i in tqdm(range(100), desc="Processing", unit="item"):
                time.sleep(0.1)
            print(f"🔍 {absolute_file_path} is a file!")
            if is_programming_file(absolute_file_path):
                source_code_analyzer.run_scan(absolute_file_path)
            if is_executable_file(absolute_file_path):
                leaf_analyzer.run_scan(absolute_file_path)
                yara_analyzer.run_scan(absolute_file_path)
                clamav_analyzer.run_scan(absolute_file_path)
                r2ai_analyzer.run_scan(absolute_file_path)
            if is_log_file(absolute_file_path):
                log_analyzer_ollama.run_scan(absolute_file_path)
        else:
            if file_path.is_dir():
                for filename in os.listdir(file_path.absolute()):
                    run_scan(os.path.join(str(file_path), filename))
    else:
        print(f"{file_path} doesn't exists!")


if __name__ == "__main__":
    banner = pyfiglet.figlet_format("Security Monster")
    print(banner)
    print("""
    ****************************************************
    *              By Vincenzo Amoruso                 *
    *               AA 2025/2026                       *
    *  Corso di laurea in: Sicurezza Informatica LM-66 *
    *           Relatore: Prof. Davide Berardi         *
    *           Insegnamento di: Cybersecurity         *
    *           Vers.  0.1 20250910                    *
    ****************************************************
    """)

    print("Python Prompt is active. Type 'exit' to quit or 'help' for a complete command list.")

    while True:
        try:
            user_input = input(">>> ").strip()
            if not esegui_comando(user_input):
                break
        except KeyboardInterrupt:
            print("\nUscita forzata con Ctrl+C.")
            break
        except EOFError:
            print("\nFine dell'input. Esco.")
            break

    print("Prompt terminato.")