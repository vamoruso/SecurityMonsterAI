#!/usr/bin/env python3
"""
log_analyzer_ollama.py
Analizza file di log (.log, .txt, .pcap, .evtx) con IA locale (Ollama) per rilevare traffico anomalo.
Usa 3 modelli in cascata. Segnala se discordanti.
"""

import sys
import os
import json
import re
import ollama
from typing import Dict, List, Any

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


# ✅ Modelli Ollama
MODELS = [
    "codellama:latest",
    "llama2:latest",
    "mistral:latest"
]

# 🧠 Prompt per analisi log
PROMPT_TEMPLATE = """
Analizza i seguenti log/eventi e rispondi SOLO in formato JSON valido, senza testo aggiuntivo.

Identifica:
1. "anomalous" — True se rilevi traffico/eventi anomali (es. scansione porte, accessi ripetuti, errori critici), False altrimenti.
2. "patterns" — Lista di pattern anomali trovati (es. "SSH brute force", "Flood UDP", "Accesso amministratore fuori orario"). Se nessuno, lista vuota.
3. "risk_level" — Livello di rischio: "low", "medium", "high".
4. "explanation" — Breve spiegazione (max 200 caratteri).

Esempio di risposta:
{{
  "anomalous": true,
  "patterns": ["SSH brute force from 192.168.1.100", "Multiple failed logins"],
  "risk_level": "high",
  "explanation": "Rilevati 50 tentativi di login SSH falliti in 2 minuti."
}}

LOG/EVENTI:
"""


class LogAnalyzer:
    def __init__(self, models: List[str] = None):
        self.models = models or MODELS

    def read_log_file(self, filepath: str) -> str:
        """Legge e pre-processa il file in base all'estensione."""
        ext = os.path.splitext(filepath)[1].lower()

        if ext == ".pcap":
            return self._parse_pcap(filepath)
        elif ext == ".evtx":
            return self._parse_evtx(filepath)
        elif ext in [".log", ".txt"]:
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

    def query_model(self, model: str, prompt: str) -> Dict[str, Any]:
        """Interroga un modello Ollama e restituisce la risposta parsata come JSON."""
        try:
            response = ollama.chat(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                options={"temperature": 0.1}
            )

            raw_response = response['message']['content'].strip()

            # Rimuovi markdown code block se presente
            if raw_response.startswith("```json"):
                raw_response = raw_response[7:]
            if raw_response.endswith("```"):
                raw_response = raw_response[:-3]

            return json.loads(raw_response)

        except json.JSONDecodeError as e:
            return {
                "error": f"❌ JSON non valido da {model}: {str(e)}",
                "raw_response": raw_response[:500]
            }
        except Exception as e:
            return {
                "error": f"❌ Errore con modello {model}: {str(e)}"
            }

    def analyze_logs(self, content: str) -> Dict[str, Any]:
        """Esegue l'analisi con tutti i modelli e confronta i risultati."""
        results = {}
        for model in self.models:
            print(f"[+] Interrogando {model}...")
            prompt = PROMPT_TEMPLATE.format(content=content)
            result = self.query_model(model, prompt)
            results[model] = result

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
        """Genera un report leggibile."""
        lines = []
        lines.append("=" * 70)
        lines.append(f"🔍 ANALISI LOG: {filepath}")
        lines.append("=" * 70)

        consensus = analysis["consensus"]
        results = analysis["log_analysis"]

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
                    lines.append(f"   📄 Anteprima: {result['raw_response']}")
            else:
                lines.append(f"🚨 Anomalo: {result.get('anomalous', 'N/D')}")
                lines.append(f"📊 Pattern: {', '.join(result.get('patterns', [])) or 'Nessuno'}")
                lines.append(f"📈 Rischio: {result.get('risk_level', 'N/A')}")
                lines.append(f"💬 Spiegazione: {result.get('explanation', 'N/A')}")
            lines.append("")

        # Consenso finale
        lines.append("-" * 70)
        lines.append("📌 SINTESI CONSENSO:")
        lines.append(f" - Anomalo: {consensus['anomalous_consensus']}")
        lines.append(f" - Pattern: {consensus['patterns_consensus'] or 'DISCORDANZA'}")
        lines.append(f" - Rischio: {consensus['risk_level_consensus'] or 'DISCORDANZA'}")

        return "\n".join(lines)

def run_scan(filepath):
    ext = os.path.splitext(filepath)[1].lower()
    if ext not in [".log", ".txt", ".pcap", ".evtx"]:
        print(f"❌ Estensione non supportata: {ext}")
        sys.exit(1)

    analyzer = LogAnalyzer()
    try:
        print(f"[+] Lettura file: {filepath}")
        content = analyzer.read_log_file(filepath)
        print(f"[+] Contenuto estratto ({len(content)} caratteri). Inizio analisi IA...")

        analysis = analyzer.analyze_logs(content)
        report = analyzer.generate_report(filepath, analysis)
        print(report)

        # Salva report
        report_file = filepath + ".analysis.txt"
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"\n✅ Report salvato in: {report_file}")

    except Exception as e:
        print(f"❌ Errore: {e}")
        sys.exit(1)

def main():
    if len(sys.argv) < 2:
        print("Uso: python log_analyzer_ollama.py <percorso_file>")
        print("Estensioni supportate: .log, .txt, .pcap, .evtx")
        sys.exit(1)

    filepath = sys.argv[1]
    ext = os.path.splitext(filepath)[1].lower()
    if ext not in [".log", ".txt", ".pcap", ".evtx"]:
        print(f"❌ Estensione non supportata: {ext}")
        sys.exit(1)

    analyzer = LogAnalyzer()
    try:
        print(f"[+] Lettura file: {filepath}")
        content = analyzer.read_log_file(filepath)
        print(f"[+] Contenuto estratto ({len(content)} caratteri). Inizio analisi IA...")

        analysis = analyzer.analyze_logs(content)
        report = analyzer.generate_report(filepath, analysis)
        print(report)

        # Salva report
        report_file = filepath + ".analysis.txt"
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"\n✅ Report salvato in: {report_file}")

    except Exception as e:
        print(f"❌ Errore: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()