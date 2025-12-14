#!/usr/bin/env python3
"""
log_analyzer.py
Analizza file di log (.log, .txt, .pcap, .evtx) con IA locale (Ollama) per rilevare traffico anomalo.
Usa 3 modelli in cascata. Segnala se discordanti.
"""
import shutil
import sys
import os
import json
import re
import traceback
from datetime import datetime
from multiprocessing import Pool

import ollama
from typing import Dict, List, Any

from rich import box
from rich.console import Console
from rich.table import Table

from SecModule import common_utils
from SecModule.ai_model_manager import ai_model_manager
from SecModule.common_utils import is_log_file, pad_to_80, is_pcap
from SecModule.constants import LOG_PROMPT_TEMPLATE, LOG_AI_MODELS
from SecModule.file_reader import FileReader
from SecModule.progress_utils import ProgressManager

# 🧩 Import librerie ad-hoc (se disponibili)
try:
    from scapy.all import rdpcap, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import Evtx.Evtx as evtx
    EVTX_AVAILABLE = True
except ImportError:
    EVTX_AVAILABLE = False






class LogAnalyzer:
    def __init__(self, models: List[str] = None):
        self.models = models or LOG_AI_MODELS
        self.aimodelmanager = ai_model_manager()
        self.pm = ProgressManager()

    def read_log_file(self, filepath: str) -> str:
        """Legge e pre-processa il file in base all'estensione."""
        ext = os.path.splitext(filepath)[1].lower()

        if is_pcap(filepath):
            return self._parse_pcap(filepath)
        elif ext == ".evtx":
            return self._parse_evtx(filepath)
        elif is_log_file(filepath):
            return self._read_text_file(filepath)
        else:
            raise ValueError(f"Estensione non supportata: {ext}")

    def _read_text_file(self, filepath: str) -> str:
        """Legge file di testo generico."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return f.read()
        except UnicodeDecodeError:
            with open(filepath, 'r', encoding='latin-1') as f:
                return f.read()

    def _parse_pcap(self, filepath: str) -> str:
        """Estrae info base da file .pcap."""
        if not SCAPY_AVAILABLE:
            return f"[ERRORE] Libreria 'scapy' non installata. Contenuto grezzo:\n{self._read_text_file(filepath)}"

        packets = rdpcap(filepath)
        lines = []
        for pkt in packets[:100]:  # Limita a 100 pacchetti per evitare overload
            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "Other"
                sport = pkt[TCP].sport if TCP in pkt else pkt[UDP].sport if UDP in pkt else "-"
                dport = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport if UDP in pkt else "-"
                lines.append(f"[IP] {src}:{sport} -> {dst}:{dport} ({proto})")
        return "\n".join(lines) if lines else "[PCAP] Nessun pacchetto IP trovato."

    def _parse_evtx(self, filepath: str) -> str:
        """Estrae eventi da file .evtx (Windows Event Log)."""
        if not EVTX_AVAILABLE:
            return f"[ERRORE] Libreria 'python-evtx' non installata. Contenuto grezzo:\n{self._read_text_file(filepath)}"

        lines = []
        with evtx.Evtx(filepath) as log:
            for record in log.records()[:50]:  # Limita a 50 eventi
                xml = record.xml()
                # Estrai timestamp e descrizione semplice
                timestamp = re.search(r"<TimeCreated SystemTime='([^']+)'", xml)
                event_id = re.search(r"<EventID[^>]*>(\d+)</EventID>", xml)
                if timestamp and event_id:
                    lines.append(f"[EVENT] ID:{event_id.group(1)} at {timestamp.group(1)}")
        return "\n".join(lines) if lines else "[EVTX] Nessun evento trovato."
    def ask_modell_thread(self, prompt: str, index: int, model: str):
        print()
        pm1 = self.pm;
        desc_start_raw = f"[{index}] Analisi in corso con modello IA \033[1m{model}\033[0m..."
        desc_end_raw = f"✅ Il modello IA \033[1m{model}\033[0m ha finito"

        pm1.start_spinner(
            desc_start=pad_to_80(desc_start_raw),
            desc_end=pad_to_80(desc_end_raw),
            charset='braille'
        )
        result, elapsed_time = self.aimodelmanager.query_model(model=model, prompt=prompt)
        pm1.stop()
        return (model, result, elapsed_time)

    def ask_modell_parallel(self, log: str, models: list, aimodelmanager, max_workers=3):
        prompts = [LOG_PROMPT_TEMPLATE.format(content=log) for _ in models]
        args = [(prompt, i + 1, model) for i, (prompt, model) in enumerate(zip(prompts, models))]

        with Pool(processes=max_workers) as p:
            risultati = p.starmap(self.ask_modell_thread, args)

        # Aggiunge i dati alle statistiche
        for model, _, elapsed_time in risultati:
            ai_model_manager.put_timing_data(model, elapsed_time)

        # results = {model: result for model, result in risultati}
        results = {model: result for model, result, _ in risultati}

        return results
    def analyze_logs(self, content: str) -> Dict[str, Any]:
        """Esegue l'analisi con tutti i modelli e confronta i risultati."""
        """Esegue l'analisi con tutti i modelli e confronta i risultati."""
        results = {}
        results = self.ask_modell_parallel(log=content, models=self.models, aimodelmanager=self.aimodelmanager)
        # Confronto tra modelli
        consensus = self.check_consensus(results)
        return {"log_analysis": results, "consensus": consensus}

    def check_consensus(self, results: Dict[str, Dict]) -> Dict[str, Any]:
        """Controlla consenso su anomalie, pattern e livello di rischio."""
        anomalous_votes = []
        pattern_sets = []
        risk_votes = []

        for model, result in results.items():
            if "error" in result:
                continue
            anomalous_votes.append(result.get("anomalous", False))
            pattern_sets.append(set(result.get("patterns", [])))
            risk_votes.append(result.get("risk_level", "low"))

        # Consenso su anomalia
        anomalous_agree = len(set(anomalous_votes)) == 1 if anomalous_votes else False
        anomalous_consensus = anomalous_votes[0] if anomalous_votes and anomalous_agree else None

        # Consenso su pattern
        pattern_agree = len(set(frozenset(p) for p in pattern_sets)) == 1 if pattern_sets else False
        pattern_consensus = list(pattern_sets[0]) if pattern_sets and pattern_agree else None

        # Consenso su rischio
        risk_agree = len(set(risk_votes)) == 1 if risk_votes else False
        risk_consensus = risk_votes[0] if risk_votes and risk_agree else None

        # Segnala problemi se c'è disaccordo
        potential_issues = []
        if not anomalous_agree and len(anomalous_votes) > 1:
            potential_issues.append("I modelli non concordano sulla presenza di anomalie.")
        if not pattern_agree and len(pattern_sets) > 1:
            potential_issues.append("I modelli non concordano sui pattern anomali trovati.")
        if not risk_agree and len(risk_votes) > 1:
            potential_issues.append("I modelli non concordano sul livello di rischio.")

        return {
            "anomalous_consensus": anomalous_consensus,
            "patterns_consensus": pattern_consensus,
            "risk_level_consensus": risk_consensus,
            "potential_issues": potential_issues,
            "agreement": len(potential_issues) == 0
        }

    def generate_report(self, filepath: str, analysis: Dict[str, Any]) -> str:
        consensus = analysis["consensus"]
        results = analysis["log_analysis"]

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
        table = Table(title=f"🔍 Analisi anomalie per il file di log {filepath}", box=box.ROUNDED,expand=True)
        table.add_column("Issue", justify="left", style="cyan")
        COLUMNS += 1
        for modello, result in results.items():
            COLUMNS += 1
            table.add_column(modello, justify="center", overflow="fold", ratio=1)

        matrix = [["" for _ in range(COLUMNS)] for _ in range(ROWS)]

        matrix[0][0] = "🚨 Anomalo"
        matrix[1][0] = "📊 Pattern"
        matrix[2][0] = "📈 Rischio"
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

                matrix[0][off_set + colum_start] = str(result.get('anomalous', 'N/D'))
                matrix[1][off_set + colum_start] =', '.join(result.get('patterns', [])) or 'Nessuno'
                matrix[2][off_set + colum_start] = result.get('risk_level', 'N/A')
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
        anomalous = "❌ Sì" if consensus['anomalous_consensus'] else "✅ No"
        patterns = consensus['patterns_consensus'] or "⚠️ DISCORDANZA"
        risk_level = consensus['risk_level_consensus'] or "⚠️ DISCORDANZA"

        consensus_table.add_row("Anomalo", anomalous)
        consensus_table.add_row("Pattern", patterns)
        consensus_table.add_row("Rischio", risk_level)

        return table,consensus_table
def run_scan(filepath_or_url):
    analyzer = LogAnalyzer()
    filereader = FileReader()

    print(f"[+] Analisi con IA del file di log {filepath_or_url}")
    result = filereader.load(filepath_or_url)

    files_list = []
    if isinstance(result, str):
        files_list.append(filepath_or_url)
    else:
        files_list = result

    report_file = common_utils.normalizza_nome_log(filepath_or_url)

    try:
        for filepath in files_list:
            if (is_log_file(filepath)):
                content = analyzer.read_log_file(filepath)
                print(f"[+] File letto: {filepath} ({len(content)} caratteri)")
                analysis = analyzer.analyze_logs(content)
                report = analyzer.generate_report(filepath, analysis)
                with open(report_file, "a", encoding="utf-8") as f:
                    f.write(report + "\n")
            else:
                print(f"[+] Il file {filepath} non è di log.")
            # Salva report su file
        print(f"\n✅ Report salvato in: {report_file}")
        ai_model_manager.print_timing_report()
    except Exception as e:
        tb = traceback.extract_tb(e.__traceback__)
        line_number = tb[-1].lineno
        filename, lineno, func, text = tb[-1]
        print(f"❌ Errore: {e} in {filename}, funzione {func}, riga {lineno}")
        sys.exit(1)

def main():
    if len(sys.argv) < 2:
        print("Uso: python log_analyzer_ollama.py <percorso_file>")
        print("Estensioni supportate: .log, .txt, .pcap, .evtx")
        sys.exit(1)

    filepath = sys.argv[1]
    run_scan(filepath)


if __name__ == "__main__":
    main()