import sys
import os
import json

import ollama
from typing import Dict, List, Any

from SecModule.ai_model_manager import ai_model_manager
from SecModule.progress_utils import ProgressManager

# Configurazione modelli
MODELS = [
    "qwen2.5-coder:32b",
    "codellama:latest",
    #"llama2:latest",
    # "mistral:latest",
    "deepseek-coder:33b-instruct-q5_K_M",

]

PROMPT_TEMPLATE = """
Analizza il seguente codice sorgente e rispondi SOLO in formato JSON valido, senza commenti o testo aggiuntivo.

Identifica:
1. "malicious" — True se contiene codice malevolo (es. reverse shell, keylogger, download eseguibili), False altrimenti.
2. "vulnerabilities" — Lista di vulnerabilità trovate (es. "SQL injection", "buffer overflow", "hardcoded password"). Se nessuna, lista vuota.
3. "logical_errors" — Lista di errori logici o bug potenziali (es. "divisione per zero", "variabile non inizializzata", "ciclo infinito"). Se nessuno, lista vuota.
4. "explanation" — Breve spiegazione (max 200 caratteri).
5. "cve" — Lista di codici CVE Common Vulnerabilities and Exposures se rilevati.

Esempio di risposta:
{{
  "malicious": false,
  "vulnerabilities": ["SQL injection in query"],
  "logical_errors": ["missing null check"],
  "explanation": "Il codice è sicuro ma presenta vulnerabilità SQL e manca controllo null.",
  "cve":"CVE-20231234 CVE-2022-5678"
}}

CODICE:{code}
"""

class SourceCodeAnalyzer:
    def __init__(self, models: List[str] = None):
        self.models = models or MODELS
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

    def analyze_code(self, code: str) -> Dict[str, Any]:
        """Esegue l'analisi con tutti i modelli e confronta i risultati."""
        results = {}
        for model in self.models:
            print(f"[+] Interrogando {model}...")
            self.pm.start_spinner(charset='braille')
            prompt = PROMPT_TEMPLATE.format(code=code)
            result = self.aimodelmanager.query_model(model=model, prompt=prompt)
            results[model] = result
            self.pm.stop();
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
        cve_sets = []

        for model, result in results.items():
            if "error" in result:
                continue
            malicious_votes.append(result.get("malicious", False))
            vuln_sets.append(set(result.get("vulnerabilities", [])))
            logic_sets.append(set(result.get("logical_errors", [])))
            cve_sets.append(set(result.get("cve", [])))

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
        lines = []
        lines.append("=" * 70)
        lines.append(f"🔍 ANALISI DEL FILE: {filepath}")
        lines.append("=" * 70)

        consensus = analysis["consensus"]
        results = analysis["file_analysis"]

        # Consenso globale
        lines.append(f"✅ ACCORDO TRA MODELLI: {'Sì' if consensus['agreement'] else 'NO'}")
        if not consensus['agreement']:
            lines.append("⚠️ POTENZIALI PROBLEMI:")
            for issue in consensus['potential_issues']:
                lines.append(f"   → {issue}")

        lines.append("")

        # Risultati per modello
        for model, result in results.items():
            lines.append(f"--- {model} ---")
            if "error" in result:
                lines.append(f"❌ ERRORE: {result['error']}")
                if "raw_response" in result:
                    lines.append(f"   📄 Risposta grezza: {result['raw_response']}")
            else:
                lines.append(f"😈 Malevolo: {result.get('malicious', 'N/D')}")
                lines.append(f"🛡️ Vulnerabilità: {', '.join(result.get('vulnerabilities', [])) or 'Nessuna'}")
                lines.append(f"🧠 Errori logici: {', '.join(result.get('logical_errors', [])) or 'Nessuno'}")
                lines.append(f"💬 Spiegazione: {result.get('explanation', 'N/A')}")
                lines.append(f"💬 cve: {result.get('cve', 'N/A')}")
            lines.append("")

        # Consenso finale
        lines.append("-" * 70)
        lines.append("📌 SINTESI CONSENSO:")
        lines.append(f" - Codice malevolo: {consensus['malicious_consensus']}")
        lines.append(f" - Vulnerabilità: {consensus['vulnerabilities_consensus'] or 'DISCORDANZA'}")
        lines.append(f" - Errori logici: {consensus['logical_errors_consensus'] or 'DISCORDANZA'}")

        self.aimodelmanager.print_timing_report()
        return "\n".join(lines)

def run_scan(filepath):
    analyzer = SourceCodeAnalyzer()
    try:
        code = analyzer.read_file(filepath)
        print(f"[+] File letto: {filepath} ({len(code)} caratteri)")
        analysis = analyzer.analyze_code(code)
        report = analyzer.generate_report(filepath, analysis)
        print(report)

        # Salva report su file
        report_file = filepath + ".analysis.txt"
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"\n✅ Report salvato in: {report_file}")

    except Exception as e:
        print(f"❌ Errore: {e}")
        sys.exit(1)

def main():
    if len(sys.argv) < 2:
        print("Uso: python source_code_analyzer_ollama.py <percorso_file>")
        print("Esempio: python source_code_analyzer_ollama.py malicious_sample.py")
        sys.exit(1)

    filepath = sys.argv[1]

    analyzer = SourceCodeAnalyzer()
    try:
        code = analyzer.read_file(filepath)
        print(f"[+] File letto: {filepath} ({len(code)} caratteri)")
        analysis = analyzer.analyze_code(code)
        report = analyzer.generate_report(filepath, analysis)
        print(report)

        # Salva report su file
        report_file = filepath + ".analysis.txt"
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"\n✅ Report salvato in: {report_file}")

    except Exception as e:
        print(f"❌ Errore: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()