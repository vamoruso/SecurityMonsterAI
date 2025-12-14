from collections import defaultdict

import lief
import shutil
import os
import sys
from ollama import chat
from typing import Dict, List, Any
import traceback

from rich import box
from rich.console import Console
from rich.progress import Progress
from rich.table import Table
from rich import print
from rich.progress import Progress, SpinnerColumn, TextColumn

from datetime import datetime
from multiprocessing import Pool

from SecModule import common_utils
from SecModule.ai_model_manager import ai_model_manager
from SecModule.common_utils import is_programming_file, pad_to_80, is_executable_file
from SecModule.constants import LIEF_AI_MODELS, LIEF_PROMPT_TEMPLATE, LIEF_SUPPORTED_EXTENSIONS
from SecModule.file_reader import FileReader
from SecModule.progress_utils import ProgressManager


# Valori delle caratteristiche DLL (da winnt.h)
DYNAMIC_BASE = 0x0040        # ASLR
HIGH_ENTROPY_VA = 0x0020  # 64-bit ASLR
FORCE_INTEGRITY = 0x0080     # Force Integrity
NX_COMPAT = 0x0100           # DEP compatible
NO_ISOLATION = 0x0200        # No Isolation
NO_SEH = 0x0400              # No SEH
NO_BIND = 0x0800             # No Bind
APPCONTAINER = 0x1000        # AppContainer
WDM_DRIVER = 0x2000          # WDM Driver
GUARD_CF = 0x4000            # Control Flow Guard
TERMINAL_SERVER_AWARE = 0x8000

class LiefAnalyzer:
    def __init__(self, models: List[str] = None):
        self.models = models or LIEF_AI_MODELS
        self.aimodelmanager=ai_model_manager()
        self.pm = ProgressManager()

    def is_supported_by_lief(self,filename: str) -> bool:
        import os
        ext = os.path.splitext(filename)[1].lower()
        return ext in LIEF_SUPPORTED_EXTENSIONS

    def analyze_file(self, file_path: str) -> dict:
        if not os.path.isfile(file_path):
            return {"file": file_path, "error": "File non trovato"}

        if not self.is_supported_by_lief(file_path):
            return {"file": file_path, "error": "Estensione file non supportata"}

        try:
            raw = lief.parse(file_path)
            if raw is None:
                return {"file": file_path, "error": "LIEF: file non supportato o corrotto"}

            features = {
                "file": file_path,
                "size_bytes": os.path.getsize(file_path),
            }

            # ——— Normalizzazione: LIEF restituisce una lista per .a e Fat Mach-O ———
            if isinstance(raw, list):
                # Libreria statica .a oppure Fat binary
                if all(isinstance(x, lief.COFF.Binary) for x in raw):
                    features["format"] = "STATIC_LIB_AR"
                    features["objects_count"] = len(raw)
                    # Analizziamo solo il primo oggetto per entropia ecc. (o tutti se vuoi)
                    binary = raw[0]
                else:  # Fat Mach-O
                    features["format"] = "FAT_MACHO"
                    features["architectures"] = len(raw)
                    binary = raw[0]  # prendiamo il primo slice
            else:
                binary = raw

            # ——— Determina formato in modo sicuro ———
            if hasattr(binary, "format"):
                fmt = str(binary.format).split(".")[-1].upper()
            elif isinstance(binary, lief.PE.Binary):
                fmt = "PE"
            elif isinstance(binary, lief.ELF.Binary):
                fmt = "ELF"
            elif isinstance(binary, lief.MachO.Binary):
                fmt = "MACHO"
            elif isinstance(binary, lief.COFF.Binary):
                fmt = "COFF_OBJECT"
            else:
                fmt = "UNKNOWN"
            features["format"] = fmt

            # ——— Entropia (sempre disponibile se ci sono sezioni) ———
            if hasattr(binary, "sections") and binary.sections:
                entropies = [s.entropy for s in binary.sections if s.size > 0]
                if entropies:
                    features.update({
                        "entropy_max": max(entropies),
                        "entropy_avg": sum(entropies) / len(entropies),
                        "entropy_min": min(entropies),
                        "high_entropy_sections": sum(1 for e in entropies if e > 7.0),
                    })

            # ——— Solo per formati dinamici/eseguibili (PE, ELF, MachO) ———
            if fmt in ("PE", "ELF", "MACHO"):
                # Import / funzioni importate
                if hasattr(binary, "imported_functions"):
                    #funcs = [f.name for imp in binary.imports for f in imp.entries if f.name]
                    funcs = []
                    if hasattr(binary, 'imported_functions'):
                        for lib in binary.imported_functions:
                            if hasattr(lib, 'entries'):
                                for entry in lib.entries:
                                    if hasattr(entry, 'name') and entry.name:
                                        funcs.append(entry.name)

                    features["import_count"] = len(funcs)
                    features["imported_functions"] = funcs[:100]  # limito per non esplodere
                elif hasattr(binary, "imports"):
                    count = sum(len(imp.entries) for imp in binary.imports)
                    features["import_count"] = count
                else:
                    features["import_count"] = 0

                # Librerie collegate (.so / .dll)
                if hasattr(binary, "libraries"):
                    libs = binary.libraries
                    features["libraries"] = libs
                    features["library_count"] = len(libs)
                else:
                    features["library_count"] = 0

                # Simboli esportati (utile per .so e .dll)
                if hasattr(binary, "exported_functions"):
                    exp = [f.name for f in binary.exported_functions]
                    features["export_count"] = len(exp)
                    features["exports"] = exp[:100]

               # Flag di protezione ELF/PE
                if fmt == "ELF":
                    features["nx"] = binary.has_nx
                    features["pie"] = "EXEC" in [str(s.flags) for s in binary.segments]

                if fmt == "PE":
                    #hdr = binary.header
                    hdr = binary.optional_header
                    features["aslr"] = (hdr.dll_characteristics & DYNAMIC_BASE) != 0
                    features["dep"] = (hdr.dll_characteristics & NX_COMPAT) != 0
                    # Per HIGH_ENTROPY_VA - usa l'optional header
                    if hdr:
                        features["high_entropy_va"] = (hdr.dll_characteristics & HIGH_ENTROPY_VA) != 0
                    else:
                        features["high_entropy_va"] = False

            else:
                # Per .o, .a, COFF object → niente import/export
                features["import_count"] = 0
                features["library_count"] = 0
                features["export_count"] = 0

            # ——— Overlay (dati alla fine del file – comune in packer/malware) ———
            if hasattr(binary, "overlay") and binary.overlay:
                ov = binary.overlay
                features["has_overlay"] = True
                features["overlay_size"] = len(ov)

                #features["overlay_entropy"] = lief.PE.entropy(ov) if fmt == "PE" else lief.ELF.entropy(ov)
                try:
                    if fmt == "PE":
                        features["overlay_entropy"] = lief.PE.Binary.entropy(ov) if hasattr(lief.PE.Binary,
                                                                                            'entropy') else 0.0
                    else:  # ELF
                        features["overlay_entropy"] = lief.ELF.Binary.entropy(ov) if hasattr(lief.ELF.Binary,
                                                                                             'entropy') else 0.0
                except:
                    features["overlay_entropy"] = 0.0

            else:
                features["has_overlay"] = False

            # ——— Rich Header (solo PE, indica compilatore) ———
            if fmt == "PE" and hasattr(binary, "rich_header") and binary.rich_header:
                features["rich_header_entries"] = len(binary.rich_header.entries)

            return features

        except Exception as e:
            import traceback
            return {
                "file": file_path,
                "error": f"LIEF exception: {str(e)}",
                "traceback": traceback.format_exc()
            }

    def analyze_entropy(self, features: str) -> Dict[str, Any]:
        """Esegue l'analisi con tutti i modelli e confronta i risultati."""
        results = {}
        results = self.ask_modell_parallel(features=features, models=self.models, aimodelmanager=self.aimodelmanager)
        # Confronto tra modelli
        consensus = self.check_consensus(results)

        return {
            "file_analysis": results,
            "consensus": consensus
        }

    def ask_modell_thread(self,prompt: str, index: int, model: str):
        print()
        pm1=self.pm;
        desc_start_raw = f"[LIEF] [{index}] Analisi in corso dati LIEF con modello IA \033[1m{model}\033[0m..."
        desc_end_raw = f"[LIEF] ✅ Il modello IA \033[1m{model}\033[0m ha finito"

        pm1.start_spinner(
            desc_start=pad_to_80(desc_start_raw),
            desc_end=pad_to_80(desc_end_raw),
            charset='braille'
                          )
        result, elapsed_time = self.aimodelmanager.query_model(model=model, prompt=prompt)
        pm1.stop()
        return (model, result,elapsed_time)

    def ask_modell_parallel(self, features: str, models: list, aimodelmanager, max_workers=3):
        prompts = [LIEF_PROMPT_TEMPLATE.format(features=features) for _ in models]
        args = [(prompt, i + 1, model) for i, (prompt, model) in enumerate(zip(prompts, models))]

        with Pool(processes=max_workers) as p:
            risultati = p.starmap(self.ask_modell_thread, args)

        # Aggiunge i dati alle statistiche
        for model, _, elapsed_time in risultati:
            ai_model_manager.put_timing_data(model, elapsed_time)

        #results = {model: result for model, result in risultati}
        results = {model: result for model, result, _ in risultati}

        return results
    def check_consensus(self, results: Dict[str, Dict]) -> Dict[str, Any]:
        """Controlla se i modelli sono d'accordo o no."""
        malware_likelihood_sets = []
        reasoning_sets = []
        indicators_sets = []

        for model, result in results.items():
            if "error" in result:
                continue
            malware_likelihood_sets.append(result.get("malware_likelihood", "low"))
            reasoning_sets.append(set(result.get("reasoning", [])))
            indicators_sets.append(set(result.get("indicators", [])))


        # Controllo consenso su "malevolo"
        malware_likelihood_agree = len(set(frozenset(v) for v in malware_likelihood_sets)) == 1 if malware_likelihood_sets else False
        malware_likelihood_consensus = malware_likelihood_sets[0] if malware_likelihood_sets and malware_likelihood_agree else None

        # Controllo consenso su vulnerabilità
        reasoning_agree = len(set(frozenset(v) for v in reasoning_sets)) == 1 if reasoning_sets else False
        reasoning_consensus = list(reasoning_sets[0]) if reasoning_sets and reasoning_agree else None

        # Controllo consenso su errori logici
        indicators_agree = len(set(frozenset(l) for l in indicators_sets)) == 1 if indicators_sets else False
        indicators_consensus = list(indicators_sets[0]) if indicators_sets and indicators_agree else None

        # Segnala problemi se c'è disaccordo
        potential_issues = []
        if not malware_likelihood_agree and len(malware_likelihood_sets) > 1:
            potential_issues.append("I modelli non concordano sulla livello di rischio.")
        if not reasoning_agree and len(reasoning_sets) > 1:
            potential_issues.append("I modelli non concordano sulle motivazioni trovate.")
        if not indicators_agree and len(indicators_sets) > 1:
            potential_issues.append("I modelli non concordano sugli indicatori trovati.")

        return {
            "malware_likelihood_consensus": malware_likelihood_consensus,
            "reasoning_consensus": reasoning_consensus,
            "indicators_consensus": indicators_consensus,
            "potential_issues": potential_issues,
            "agreement": len(potential_issues) == 0
        }

    def generate_report(self, filepath: str, entropy: Dict[str, Any], analysis: Dict[str, Any]) -> str:
        """Genera un report leggibile."""

        consensus = analysis["consensus"]
        results = analysis["file_analysis"]

        if (len(results.items())==0):
            return ""

        table,consensus_table=self.print_grid(filepath, entropy, results, consensus)
        # 2. Usa Console per renderizzare la tabella in una stringa
        term_width = shutil.get_terminal_size().columns
        # Imposta larghezza solo se > 120
        console = Console(width=term_width if term_width > 120 else None, record=True)  # record=True permette di esportare

        now = datetime.now()
        console.print(now.strftime("%Y-%m-%d %H:%M:%S").rjust(50))
        console.print(table)
        console.print(consensus_table)
        # 3. Ottieni il testo come stringa
        text_output = console.export_text()

        return text_output

    def print_grid(self, filepath, entropy, results, consensus):

        # --- 1. Crea la tabella delle features ---
        features_table = Table(
            title="[LIEF] 📊 Caratteristiche estratte dal file",
            box=box.ROUNDED,
            expand=True,
            show_header=False  # opzionale: puoi anche usare header se preferisci
        )
        features_table.add_column("Caratteristica", style="bold yellow", width=25)
        features_table.add_column("Valore", style="green")

        # Aggiungi le coppie chiave-valore da `features`
        # Puoi personalizzare l'ordine o filtrare solo quelle rilevanti
        for key, value in entropy.items():
            features_table.add_row(str(key), str(value))

        ROWS=3
        COLUMNS=0
        lines = []
        table = Table(title=f" [LIEF] 🔍 Analisi entropia con IA per il file {filepath}", box=box.ROUNDED,expand=True)
        table.add_column("Issue\\Modello", justify="left", style="cyan")
        COLUMNS += 1
        for modello, result in results.items():
            COLUMNS += 1
            table.add_column(modello, justify="center", overflow="fold", ratio=1)

        matrix = [["" for _ in range(COLUMNS)] for _ in range(ROWS)]

        matrix[0][0] = "😈 Rischio "
        matrix[1][0] = "🔍️ Descrizione"
        matrix[2][0] = "🧠 indicatori"

        off_set = 1
        colum_start = 0

        for model, result in results.items():
            # lines.append(f"--- {model} ---")
            if "error" in result:
                lines.append(f"❌ ERRORE: {result['error']}")
                if "raw_response" in result:
                    lines.append(f"   📄 Risposta grezza: {result['raw_response']}")
            else:

                matrix[0][off_set + colum_start] = ("💀" if str(
                    result.get('malware_likelihood', 'N/D')).lower() == 'high' else "✅") + str(result.get('malware_likelihood', 'N/D'))
                matrix[1][off_set + colum_start] = result.get('reasoning','Nessuna')
                matrix[2][off_set + colum_start] = ', '.join(result.get('indicators', [])) or 'Nessuno'
                colum_start = colum_start + 1
        lines.append("")
        # Lettura
        for riga in matrix:
            # Aggiunta riga usando unpacking
            if len(riga) == COLUMNS:
                table.add_row(*riga)
                table.add_section()
            else:
                print(f"⚠️ Riga ignorata: {riga} (attese {COLUMNS} colonne)")
        table.add_section()

        # Rileva larghezza terminale
        term_width = shutil.get_terminal_size().columns
        # Imposta larghezza solo se > 120
        console = Console(width=term_width if term_width > 120 else None, force_terminal=True)
        # 3. Tabella del consenso (la tua)
        consensus_table = Table(box=box.ROUNDED, show_header=False, padding=(0, 1))
        consensus_table.add_column(style="bold", width=30)
        consensus_table.add_column()

        # Accordo globale
        agreement_text = "✅ Sì" if consensus['agreement'] else "❌ NO"
        consensus_table.add_row("Accordo tra modelli", agreement_text)

        # Potenziali problemi
        if not consensus['agreement']:
            issues = "\n".join(f"→ {issue}" for issue in consensus['potential_issues'])
            consensus_table.add_row("⚠️ Potenziali problemi", issues)

        # Sintesi
        consensus_table.add_section()
        malware_likelihood = str(consensus['malware_likelihood_consensus'] or "⚠️ DISCORDANZA")
        reasoning = str(consensus['reasoning_consensus'] or "⚠️ DISCORDANZA")
        indicators = str(consensus['indicators_consensus'] or "⚠️ DISCORDANZA")

        if malware_likelihood is not None:
            malware_likelihood = "".join(malware_likelihood) if isinstance(malware_likelihood, (list, tuple)) else str(
                malware_likelihood or "N/A")

            consensus_table.add_row("Rischio malware", malware_likelihood)
        if reasoning is not None:
           consensus_table.add_row("Spiegazione", reasoning)
        if indicators is not None:
           consensus_table.add_row("Indicatori", indicators)

        # --- 3. UNISCI LE DUE TABELLE IN UN UNICO RENDERIZZABILE ---
        combined_table = Table.grid(padding=(1, 0))  # padding verticale/horiz
        combined_table.add_row(features_table)
        combined_table.add_row(table)

        return combined_table,consensus_table


def run_scan(filepath_or_url):
    analyzer = LiefAnalyzer()
    filereader = FileReader()
    print(f"[LIEF] 🌿  version: {lief.__version__}")
    print(f"[LIEF] [+] Analisi con IA dei file binary/eseguibili di {filepath_or_url}")
    result = filereader.load(filepath_or_url)

    files_list = []
    if isinstance(result, str):
        files_list.append(filepath_or_url)
    else:
        files_list = result

    report_file = common_utils.normalizza_nome_log(filepath_or_url)

    try:
        at_least_one=False
        for filepath in files_list:
            if (is_executable_file(filepath) and analyzer.is_supported_by_lief(filepath)):
                entropy = analyzer.analyze_file(filepath)
                print(f"[LIEF] 🗂️ File elaborato ")
                analysis = analyzer.analyze_entropy(entropy)
                report = analyzer.generate_report(filepath, entropy, analysis)
                if (len(str(report))>0):
                    at_least_one = True
                    with open(report_file, "a", encoding="utf-8") as f:
                        f.write(report + "\n")
            else:
                print(f"[LIEF]🗂️ Il file {filepath} non è binary/eseguibile o estensione non supportata.")
            # Salva report su file
        if (at_least_one):
            print(f"\n[LIEF] ✅ Report salvato in: {report_file}")
            ai_model_manager.print_timing_report()
    except Exception as e:
        tb = traceback.extract_tb(e.__traceback__)
        print(f"[LIEF]❌ Errore: {e}")
        print("[LIEF]📌 Stack trace completo:")
        for i, frame in enumerate(tb):
            print(f"[LIEF]   [{i}] File: {frame.filename}")
            print(f"[LIEF]        Funzione: {frame.name}")
            print(f"[LIEF]        Riga: {frame.lineno}")
            print(f"[LIEF]        Codice: {frame.line}")
        sys.exit(1)

def main():
    if len(sys.argv) < 2:
        print("Uso: python leaf_analyzer.py <percorso_file>")
        print("Esempio: python leaf_analyzer.py malicious_sample.exe")
        sys.exit(1)

    filepath = sys.argv[1]
    run_scan(filepath)

if __name__ == "__main__":
    main()