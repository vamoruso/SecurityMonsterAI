import shutil
import sys
import os
import json
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from multiprocessing import Pool

import ollama
from typing import Dict, List, Any

from rich import box
from rich.console import Console
from rich.progress import Progress
from rich.table import Table
from rich import print
from rich.progress import Progress, SpinnerColumn, TextColumn

from SecModule import common_utils
from SecModule.ai_model_manager import ai_model_manager
from SecModule.common_utils import is_programming_file, pad_to_80
from SecModule.constants import SOURCE_CODE_MODELS, SOURCE_CODE_PROMPT_TEMPLATE
from SecModule.file_reader import FileReader
from SecModule.progress_utils import ProgressManager
from debug_config import DEBUG_MODE


class SourceCodeAnalyzer:
    def __init__(self, models: List[str] = None):
        self.models = models or SOURCE_CODE_MODELS
        self.aimodelmanager=ai_model_manager()
        self.pm = ProgressManager()

    def read_file(self, filepath: str) -> str:
        """Legge il contenuto del file sorgente."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"❌ File non trovato: {filepath}")
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return f.read()
        except UnicodeDecodeError:
            with open(filepath, 'r', encoding='latin-1') as f:
                return f.read()

    def ask_modell_thread(self,prompt: str, index: int, model: str):
        print()
        pm1=self.pm;
        desc_start_raw = f"[{index}] Analisi in corso con modello IA \033[1m{model}\033[0m..."
        desc_end_raw = f"✅ Il modello IA \033[1m{model}\033[0m ha finito"

        pm1.start_spinner(
            desc_start=pad_to_80(desc_start_raw),
            desc_end=pad_to_80(desc_end_raw),
            charset='braille'
                          )
        result, elapsed_time = self.aimodelmanager.query_model(model=model, prompt=prompt)
        pm1.stop()
        return (model, result,elapsed_time)

    def ask_modell_parallel(self, code: str, models: list, aimodelmanager, max_workers=3):
        prompts = [SOURCE_CODE_PROMPT_TEMPLATE.format(code=code) for _ in models]
        args = [(prompt, i + 1, model) for i, (prompt, model) in enumerate(zip(prompts, models))]

        with Pool(processes=max_workers) as p:
            risultati = p.starmap(self.ask_modell_thread, args)

        # Aggiunge i dati alle statistiche
        for model, _, elapsed_time in risultati:
            ai_model_manager.put_timing_data(model, elapsed_time)

        #results = {model: result for model, result in risultati}
        results = {model: result for model, result, _ in risultati}

        return results

    def analyze_code(self, code: str) -> Dict[str, Any]:
        """Esegue l'analisi con tutti i modelli e confronta i risultati."""
        results = {}
        results = self.ask_modell_parallel(code=code, models=self.models, aimodelmanager=self.aimodelmanager)
        # Confronto tra modelli
        consensus = self.check_consensus(results)

        return {
            "file_analysis": results,
            "consensus": consensus
        }

    def check_consensus(self, results: Dict[str, Dict]) -> Dict[str, Any]:
        """Controlla se i modelli sono d'accordo o no."""
        malicious_votes = []
        vuln_sets = []
        logic_sets = []

        for model, result in results.items():
            if "error" in result:
                continue
            malicious_votes.append(result.get("malicious", False))
            vuln_sets.append(set(result.get("vulnerabilities", [])))
            logic_sets.append(set(result.get("logical_errors", [])))

        # Controllo consenso su "malevolo"
        malicious_agree = len(set(malicious_votes)) == 1 if malicious_votes else False
        malicious_consensus = malicious_votes[0] if malicious_votes and malicious_agree else None

        # Controllo consenso su vulnerabilità
        vuln_agree = len(set(frozenset(v) for v in vuln_sets)) == 1 if vuln_sets else False
        vuln_consensus = list(vuln_sets[0]) if vuln_sets and vuln_agree else None

        # Controllo consenso su errori logici
        logic_agree = len(set(frozenset(l) for l in logic_sets)) == 1 if logic_sets else False
        logic_consensus = list(logic_sets[0]) if logic_sets and logic_agree else None

        # Segnala problemi se c'è disaccordo
        potential_issues = []
        if not malicious_agree and len(malicious_votes) > 1:
            potential_issues.append("I modelli non concordano sulla presenza di codice malevolo.")
        if not vuln_agree and len(vuln_sets) > 1:
            potential_issues.append("I modelli non concordano sulle vulnerabilità trovate.")
        if not logic_agree and len(logic_sets) > 1:
            potential_issues.append("I modelli non concordano sugli errori logici.")

        return {
            "malicious_consensus": malicious_consensus,
            "vulnerabilities_consensus": vuln_consensus,
            "logical_errors_consensus": logic_consensus,
            "potential_issues": potential_issues,
            "agreement": len(potential_issues) == 0
        }

    def generate_report(self, filepath: str, analysis: Dict[str, Any]) -> str:
        """Genera un report leggibile."""

        consensus = analysis["consensus"]
        results = analysis["file_analysis"]

        table,consensus_table=self.print_grid(filepath, results, consensus)
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

    def print_grid(self, filepath, results, consensus):

        ROWS=4
        COLUMNS=0
        lines = []
        table = Table(title=f"🔍 Vulnerabilità Rilevate per il file {filepath}", box=box.ROUNDED,expand=True)
        table.add_column("Issue\\Modello", justify="left", style="cyan")
        COLUMNS += 1
        for modello, result in results.items():
            COLUMNS += 1
            table.add_column(modello, justify="center", overflow="fold", ratio=1)

        matrix = [["" for _ in range(COLUMNS)] for _ in range(ROWS)]

        matrix[0][0] = "😈 Malevolo"
        matrix[1][0] = "🛡️ Vulnerabilita'"
        matrix[2][0] = "🧠 Errori logici"
        matrix[3][0] = "💬 Spiegazione"

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
                    result.get('malicious', 'N/D')).lower() == 'true' else "✅") + str(result.get('malicious', 'N/D'))
                matrix[1][off_set + colum_start] = ', '.join(result.get('vulnerabilities', [])) or 'Nessuna'
                matrix[2][off_set + colum_start] = ', '.join(result.get('logical_errors', [])) or 'Nessuno'
                matrix[3][off_set + colum_start] = result.get('explanation', 'N/A')
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
        malicious = "❌ Sì" if consensus['malicious_consensus'] else "✅ Nessun malware"
        vuln = str(consensus['vulnerabilities_consensus'] or "⚠️ DISCORDANZA")
        logic = str(consensus['logical_errors_consensus'] or "⚠️ DISCORDANZA")

        if malicious is not None:
            consensus_table.add_row("Codice malevolo", malicious)
        if vuln is not None:
           consensus_table.add_row("Vulnerabilità", vuln)
        if logic is not None:
           consensus_table.add_row("Errori logici", logic)

        return table,consensus_table


def run_scan(filepath_or_url):
    analyzer = SourceCodeAnalyzer()
    filereader= FileReader()

    print(f"[+] Analisi con IA del codice sorgente di {filepath_or_url}")
    result=filereader.load(filepath_or_url)

    files_list=[]
    if isinstance(result, str):
        files_list.append(filepath_or_url)
    else:
        files_list=result

    report_file = common_utils.normalizza_nome_log(filepath_or_url)

    try:
            for filepath in files_list:
                if (is_programming_file(filepath)):
                    code = analyzer.read_file(filepath)
                    print(f"[+] File letto: {filepath} ({len(code)} caratteri)")
                    analysis = analyzer.analyze_code(code)
                    report = analyzer.generate_report(filepath, analysis)
                    with open(report_file, "a", encoding="utf-8") as f:
                        f.write(report+"\n")
                else:
                    print(f"[+] Il file {filepath} non è codice sorgente.")
                # Salva report su file
            print(f"\n✅ Report salvato in: {report_file}")
            ai_model_manager.print_timing_report()
    except Exception as e:
        tb = traceback.extract_tb(e.__traceback__)
        print(f"❌ Errore: {e}")
        print("📌 Stack trace completo:")
        for i, frame in enumerate(tb):
            print(f"   [{i}] File: {frame.filename}")
            print(f"        Funzione: {frame.name}")
            print(f"        Riga: {frame.lineno}")
            print(f"        Codice: {frame.line}")
        sys.exit(1)


def main():
    if len(sys.argv) < 2:
        print("Uso: python source_code_analyzer_ollama.py <percorso_file>")
        print("Esempio: python source_code_analyzer_ollama.py malicious_sample.py")
        sys.exit(1)

    filepath = sys.argv[1]
    run_scan(filepath)

if __name__ == "__main__":
    main()