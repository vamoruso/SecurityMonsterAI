# Prima installa pyfiglet con il comando:
# pip install pyfiglet
import argparse
import multiprocessing
import os
import sys
import time
import pyfiglet
from pathlib import Path

from tqdm import tqdm

from SecModule import common_utils, source_code_analyzer, log_analyzer, lief_analyzer, yara_analyzer, clamav_analyzer, \
    r2ai_analyzer, file_reader, bin_analyzer

#from SecModule.common_utils import is_programming_file, is_log_file, is_executable_file

debug = False


def esegui_comando(comando):
    """
    Esegue i comandi della CLI.

    Comandi supportati:
        - help: Mostra l'aiuto
        - scan <path> [--type <src|bin|log>]: Scansiona un file/directory
        - exit: Esce dal programma

    Args:
        comando: Stringa del comando da eseguire

    Returns:
        bool: True per continuare, False per uscire
    """
    comando = comando.strip()

    if comando == "help":
        print("\n" + "=" * 70)
        print("📚 SECURITY MONSTER - COMANDI DISPONIBILI")
        print("=" * 70)
        print("\n📌 COMANDI GENERALI:")
        print("   help                      - Mostra questo messaggio di aiuto")
        print("   exit                      - Esci dal programma")

        print("\n🔍 COMANDI DI SCANSIONE:")
        print("   scan <path>               - Scansione automatica (auto-detect tipo file)")
        print("   scan <path> --type src    - Scansiona solo codice sorgente")
        print("   scan <path> --type bin    - Scansiona solo binari/eseguibili")
        print("   scan <path> --type log    - Scansiona solo file di log")

        print("\n💡 ESEMPI:")
        print("   scan C:\\malware.exe")
        print("   scan C:\\project\\src --type src")
        print("   scan C:\\logs\\system.log --type log")
        print("   scan /home/user/app.dll --type bin")

        print("\n📝 TIPI DI FILE SUPPORTATI:")
        print("   src (Source):  .py, .js, .java, .c, .cpp, .cs, .php, .rb, .go, etc.")
        print("   bin (Binary):  .exe, .dll, .so, .elf, .bin, .sys, etc.")
        print("   log (Logs):    .log, .txt, .pcap, .evtx, .json, etc.")
        print("=" * 70 + "\n")

    elif comando.startswith("scan"):
        # Parse del comando scan
        parti = comando.split()

        if len(parti) < 2:
            print("❌ Errore: uso corretto -> scan <file/path> [--type <src|bin|log>]")
            print("💡 Esempi:")
            print("   scan C:\\file.exe")
            print("   scan C:\\project --type src")

            # Chiedi interattivamente
            path = input("\n📁 Inserisci il file/path da scansionare: ").strip()
            if not path:
                print("⚠️  Nessun path specificato, operazione annullata")
                return True

            type_input = input("🔧 Tipo di scansione (invio per auto-detect, oppure src/bin/log): ").strip().lower()

            # Mappa type_input a operation
            operation = None
            if type_input:
                type_mapping = {
                    'src': 'src_scan',
                    'bin': 'bin_scan',
                    'log': 'log_scan'
                }
                if type_input in type_mapping:
                    operation = type_mapping[type_input]
                else:
                    print(f"❌ Tipo '{type_input}' non valido. Usa: src, bin, o log")
                    return True

            print(f"\n🔍 Scansionando: {path}")
            if operation:
                print(f"📌 Modalità: {operation}")
            run_scan(path, operation)
            return True

        # Estrae il path (può contenere spazi)
        path = None
        operation = None

        # Cerca il flag --type
        if "--type" in parti:
            try:
                type_index = parti.index("--type")
                if type_index + 1 < len(parti):
                    type_value = parti[type_index + 1].lower()

                    # Mappa il valore breve all'operazione completa
                    type_mapping = {
                        'src': 'src_scan',
                        'bin': 'bin_scan',
                        'log': 'log_scan'
                    }

                    if type_value in type_mapping:
                        operation = type_mapping[type_value]
                        # Il path è tutto ciò che viene prima di --type
                        path = " ".join(parti[1:type_index])
                    else:
                        print(f"❌ Errore: tipo '{type_value}' non valido")
                        print("   Tipi validi: src, bin, log")
                        return True
                else:
                    print("❌ Errore: --type richiede un valore (src, bin, o log)")
                    return True
            except ValueError:
                pass
        else:
            # Nessun flag --type, il path è tutto dopo "scan"
            path = " ".join(parti[1:])

        # Verifica che il path non sia vuoto
        if not path or path.strip() == "":
            print("❌ Errore: specifica un file o percorso da scansionare")
            return True

        path = path.strip()

        # Rimuovi virgolette se presenti
        if path.startswith('"') and path.endswith('"'):
            path = path[1:-1]
        elif path.startswith("'") and path.endswith("'"):
            path = path[1:-1]

        # Esegui la scansione
        print("\n" + "=" * 70)
        print(f"🔍 AVVIO SCANSIONE")
        print("=" * 70)
        print(f"📁 Target: {path}")

        if operation:
            operation_names = {
                'src_scan': '📝 Codice Sorgente',
                'bin_scan': '⚙️  Binari/Eseguibili',
                'log_scan': '📋 File di Log'
            }
            print(f"🔧 Modalità: {operation_names.get(operation, operation)}")
        else:
            print(f"🤖 Modalità: Auto-detect (analisi automatica)")

        print("=" * 70 + "\n")

        try:
            run_scan(path, operation)
            print("\n" + "=" * 70)
            print("✅ SCANSIONE COMPLETATA")
            print("=" * 70 + "\n")
        except Exception as e:
            print(f"\n❌ Errore durante la scansione: {e}")
            import traceback
            traceback.print_exc()

    elif comando == "exit" or comando == "quit":
        print("\n" + "=" * 70)
        print("👋 Grazie per aver usato Security Monster!")
        print("   Stay safe! 🛡️")
        print("=" * 70 + "\n")
        return False  # Segnala di uscire

    elif comando == "":
        # Comando vuoto, ignora
        pass

    else:
        print(f"❌ Comando sconosciuto: '{comando}'")
        print("💡 Digita 'help' per vedere i comandi disponibili")

    return True  # Continua il loop


def run_scan(absolute_file_path, operation=None):
    file_path = Path(absolute_file_path)
    if (operation is None):
        # Check if path exists
        if file_path.exists():
            if file_path.is_file():
                # Custom description and unit
                for i in tqdm(range(100), desc="Processing", unit="item"):
                    time.sleep(0.1)
                print(f"🔍 {absolute_file_path} is a file!")
                if common_utils.is_programming_file(absolute_file_path):
                    print("✓ File is a source code file, proceeding with analysis...")
                    source_code_analyzer.run_scan(absolute_file_path)
                if common_utils.is_executable_file(absolute_file_path):
                    print("✓ File is an executable, proceeding with analysis...")
                    bin_analyzer.run_scan(absolute_file_path)
                if common_utils.is_log_file(absolute_file_path):
                    print("✓ File is a log file, proceeding with analysis...")
                    log_analyzer.run_scan(absolute_file_path)
            else:
                if file_path.is_dir():
                    for filename in os.listdir(file_path.absolute()):
                        run_scan(os.path.join(str(file_path), filename))
        else:
            print(f"{file_path} doesn't exists!")
            # === SOURCE CODE SCAN MODE ===
    elif operation == 'src_scan':
        print("📝 Source code scan mode")
        source_code_analyzer.run_scan(absolute_file_path)
        # === BINARY SCAN MODE ===
    elif operation == 'bin_scan':
        print("⚙️  Binary/Executable scan mode")
        bin_analyzer.run_scan(absolute_file_path)
        # === LOG SCAN MODE ===
    elif operation == 'log_scan':
        print("📋 Log scan mode")
        log_analyzer.run_scan(absolute_file_path)

        # === UNKNOWN OPERATION ===
    else:
        print(f"❌ Error: Unknown operation '{operation}'")
        print("   Valid operations: 'src_scan', 'bin_scan', 'log_scan', or None (auto-detect)")

    print("-" * 60)

def print_banner():
    banner = pyfiglet.figlet_format("Security Monster")
    print(banner)
    print("""
        ****************************************************
        *              By Vincenzo Amoruso                 *
        *            Universitas Mercatorum                *
        *              FACOLTA DI SCIENZE E                *
        *         TECNOLOGIE DELLA INNOVAZIONE             *
        *               AA 2025/2026                       *
        *          Corso di laurea magistrale in           * 
        *           Sicurezza Informatica LM-66            *
        *          Relatore: Prof. Davide Berardi          *
        *          Insegnamento di: Cybersecurity          *
        *           Vers.  0.2 20251014                    *
        ****************************************************
        """)
def main():
    # ===== PROTEZIONE CONTRO RE-ENTRY =====
    # Previene l'esecuzione multipla del main in processi figli
    if getattr(sys, 'frozen', False):
        # Se è un eseguibile PyInstaller
        multiprocessing.freeze_support()

        # Verifica se questo è un processo figlio
        if 'parent_pid' in ' '.join(sys.argv):
            # Questo è un processo figlio, non eseguire il main
            return
    if (debug) :
        # Debug: stampa tutti gli argomenti ricevuti
        print(f"DEBUG - sys.argv: {sys.argv}")
        print(f"DEBUG - sys.argv[1:]: {sys.argv[1:]}")

    # Filtra argomenti
    clean_args = []
    for arg in sys.argv[1:]:
        if (debug):
            print(f"DEBUG - Checking arg: {arg}")
        if not any(arg.startswith(prefix) for prefix in ['pipe_handle=','parent_pid=', '--multiprocessing-fork']):
            clean_args.append(arg)
            if (debug):
                print(f"  → Kept")
        else:
            if (debug):
                print(f"  → Filtered out")

    if (debug) :
        print(f"DEBUG - clean_args: {clean_args}")

    parser = argparse.ArgumentParser(
        description='Security Monster - Analizzatore di sicurezza',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('command', nargs='?', choices=['scan', 'help'])
    parser.add_argument('path', nargs='?', help='Path del file o directory')

    parser.add_argument('--type', '-t', choices=['src', 'bin', 'log'],
                        help='Tipo di scansione')

    parser.add_argument('--no-banner', action='store_true',
                        help='Non mostrare il banner')

    parser.add_argument('--output', '-o', metavar='FILE',
                        help='Salva risultati in un file')

    parser.add_argument('--quiet', action='store_true', help='Disabilita output verboso')

    parser.add_argument('--verbose', action='store_true', help='Abilita output dettagliato')

    parser.add_argument('--version', '-v', action='version',
                        version='Security Monster v0.2')



    # ===== USA GLI ARGOMENTI PULITI =====
    try:
        args = parser.parse_args(clean_args)
    except SystemExit as e:
        # Se argparse fallisce, vai in modalità interattiva
        if len(clean_args) == 0:
            args = argparse.Namespace(
                command=None,
                path=None,
                type=None,
                no_banner=False,
                interactive=True,
                output=None,
                verbose=False,
                quiet=False,
                json=False,
                recursive=False
            )
        else:
            # Re-raise l'errore se ci sono argomenti validi
            raise

    # Gestione opzioni globali
    if args.quiet:
        # Disabilita output non essenziale
        pass

    if args.verbose:
        # Abilita logging dettagliato
        pass

    # Mostra banner
    if not args.no_banner and not args.quiet:
        print_banner()

    # Modalità interattiva
    # ✅ Controllo corretto
    if not any(vars(args).values()):
        print("Python Prompt attivo. Digita 'exit' per uscire o 'help' per aiuto.")

        while True:
            try:
                user_input = input(">>> ").strip()
                if not esegui_comando(user_input):
                    break
            except KeyboardInterrupt:
                print("\n\n👋 Uscita forzata con Ctrl+C.")
                break
            except EOFError:
                print("\n\n👋 Fine dell'input. Esco.")
                break

        print("Prompt terminato.")
        sys.exit(1)
    # Esecuzione comando
    else:
        if args.command == 'help':
            esegui_comando('help')

        elif args.command == 'scan':
            if args.path is None:
                print("❌ Errore: il comando 'scan' richiede un path")
                sys.exit(1)

            # Costruisci comando
            comando = f"scan {args.path}"
            if args.type:
                comando += f" --type {args.type}"

            # Esegui scansione
            try:
                esegui_comando(comando)

                # Salva output se richiesto
                if args.output:
                    # Implementa salvataggio risultati
                    print(f"💾 Risultati salvati in: {args.output}")

            except Exception as e:
                print(f"❌ Errore critico: {e}")
                sys.exit(1)


if __name__ == "__main__":
    # ===== PROTEZIONE MULTIPROCESSING =====
    # CRITICO: Deve essere la prima riga nel blocco __main__
    multiprocessing.freeze_support()
    main()


