#!/usr/bin/env python3
"""
analyze_with_r2ai.py — Windows 11 Compatible
Analyzes a binary file using radare2 + r2ai plugin via r2pipe.
"""
import hashlib
import json
import math
import re
import sys
import os
import subprocess
import shutil
import traceback
from typing import Dict, Counter

import r2pipe

import debug_config
from SecModule.BinReportGenerator import BinReportGenerator
from SecModule.MalwareDetector import MalwareDetector
from SecModule.constants import R2AI_MODEL_NAME, R2AI_API, R2AI_HOST_PORT, R2AI_MAX_RETRIES, R2AI_PROMPTS
from SecModule.progress_utils import Spinner


class R2aiAnalyzer:
    def __init__(self):
        self.r2 = None
        self.analysis_results = {}
        os.environ["R2_CURL"] = "1"  # Serve per attivare l'url del curl
        self.current_model = None
        self.malware_detector = MalwareDetector()
        self.report_generator = BinReportGenerator()
        self.spinner=Spinner()
    # Entropia di Shannon
    #     Entropia ≈ 0.0 → dati molto ridondanti (es. file pieno di 0)
    #     Entropia ≈ 8.0 → dati altamente casuali (possibile packing, crittografia, ecc.)
    def calculate_entropy(self,filepath):
        with open(filepath, "rb") as f:
            data = f.read()

        if not data:
            return 0.0

        # Frequenza di ogni byte
        counts = Counter(data)
        total = len(data)

        entropy = 0.0
        for count in counts.values():
            p = count / total
            entropy -= p * math.log2(p)

        return entropy

    def get_file_metadata(self, file_path: str) -> Dict:
        """Estrae metadati del file"""
        stat = os.stat(file_path)

        return {
            'size': stat.st_size,
            'created': stat.st_ctime,
            'modified': stat.st_mtime,
            'entropy': self.calculate_entropy(file_path),
            'path': file_path
        }

    def calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """Calcola gli hash del file"""
        hashes = {}
        with open(file_path, 'rb') as f:
            data = f.read()
            hashes['md5'] = hashlib.md5(data).hexdigest()
            hashes['sha1'] = hashlib.sha1(data).hexdigest()
            hashes['sha256'] = hashlib.sha256(data).hexdigest()
        return hashes

    def check_r2ai_installed(self):
        """Check if radare2 is available in PATH."""
        if not shutil.which("r2"):
            raise EnvironmentError(
                "❌ radare2 not found. Install via Scoop: 'scoop install radare2'"
            )

        """Check if r2ai plugin is installed."""
        exe = shutil.which("r2ai")
        if not exe:
            raise EnvironmentError("❌ radare2 (r2) non trovato nel PATH")



    def ensure_model_downloaded(self):
        """Ensure at least one model is downloaded."""
        model_dir = os.path.expanduser("~/.r2ai/models")
        if not os.path.exists(model_dir) or not os.listdir(model_dir):
            print("⚠️ No models found in ~/.r2ai/models")
            print("👉 Download one manually, e.g.:")
            print("   mkdir %USERPROFILE%\\.r2ai\\models")
            print("   cd %USERPROFILE%\\.r2ai\\models")
            print("   curl -L -o ggml-model-q4_0.gguf https://huggingface.co/ggml-org/ggml/resolve/main/tinyllama-1.1b/ggml-model-q4_0.gguf")
            print("Or visit: https://github.com/radareorg/r2ai#models")
            return False
        return True

    def open_file(self, file_path: str):
        """Apre il file con radare2"""
        try:
            self.r2 = r2pipe.open(file_path, flags=['-2','-w'])
            print("[R2AI][+] Analizza file binario con 'aaaa'...")
            # Initialize analysis
            self.r2.cmd('aaaa')  # Auto-analysis  ricorsiva

            return True
        except Exception as e:
            print(f"[R2AI]Errore nell'apertura del file: {e}")
            return False
    def initialize_for_model(self,model_name):
        if self.current_model == model_name:
            print(f"[R2AI][INFO] Modello '{model_name}' già inizializzato, nessuna azione.")
            return
        self.current_model = model_name
        # Ensure r2ai is loaded
        print("[R2AI]⚙️ Caricamento r2ai plugin...")
        load_result = self.r2.cmd("r2ai")
        if "Usage" not in load_result and "Error" in load_result:
            raise RuntimeError(f"[R2AI] Failed to load r2ai: {load_result}")

        # Set model if specified
        """
        if model_name:
            print(f"[+] Setting AI model: {model_name}")
            model_result = self.r2.cmd(f"r2ai -m {model_name}")
            if "Error" in model_result:
                print(f"⚠️ Model '{model_name}' may not be available. Using default.")
        """
        self.r2.cmd(f"r2ai -e api={R2AI_API}")
        self.r2.cmd(f"r2ai -e http.max_retries = {R2AI_MAX_RETRIES}")
        self.r2.cmd(f"r2ai -e model={model_name}")
        self.r2.cmd(f"r2ai -e http.backend=libcurl")
        self.r2.cmd(f"r2ai -e baseurl={R2AI_HOST_PORT}")


    def basic_analysis(self) -> Dict:
        """Esegue analisi di base"""
        print("[R2AI]🚀 Estrazione imports,exports,sections e strings ...")
        return {
            'imports': self.r2.cmd('ii'),
            'exports': self.r2.cmd('iEq'),
            'sections': self.r2.cmd('iSq'),
            'strings': self.r2.cmd('izzq'),
            'architecture': self.r2.cmd('i~arch')
        }

    def clean_json_response(self,text: str) -> str:
        """
        Rimuove delimitatori di blocco (```json ... ``` o ''' ... ''')
        e tronca eventuali note extra dopo la chiusura del JSON.
        """
        # Elimina i delimitatori di codice Markdown
        cleaned = re.sub(r"^```json\s*|\s*```$|^'''\s*|\s*'''$", "", text.strip(), flags=re.MULTILINE)

        # Trova solo la parte JSON (dalla prima [ o { fino all'ultima ] o })
        match = re.search(r"(\[.*\]|\{.*\})", cleaned, flags=re.DOTALL)

        if match:
            # 4. Usa raw_decode: legge SOLO il JSON valido, poi restituisce l'indice di fine
            try:
                text= match.group(1).strip()
                decoder = json.JSONDecoder()
                obj, end = decoder.raw_decode(text)
                # Estrai esattamente la sottostringa del JSON
                json_str = text[:end]
                return json_str.strip()
            except json.JSONDecodeError as e:
                raise ValueError(f"JSON non valido: {e}") from e
        else:
            raise ValueError("Nessun JSON valido trovato")

    def parse_items(self,text: str):
        """
        Parsa la risposta pulita come JSON.
        Ritorna una lista di dict. Solleva ValueError se il JSON non è valido.
        """
        cleaned = self.clean_json_response(text)
        try:
            if (debug_config==True):
                print(cleaned)
            return json.loads(cleaned)
        except Exception as e:
            print("json cleaned:"+cleaned)
            tb = traceback.extract_tb(e.__traceback__)
            print(f"[R2AI]❌ Errore: {e}")
            print("[R2AI]📌 Stack trace completo:")
            for i, frame in enumerate(tb):
                print(f"[R2AI]   [{i}] File: {frame.filename}")
                print(f"[R2AI]        Funzione: {frame.name}")
                print(f"[R2AI]        Riga: {frame.lineno}")
                print(f"[R2AI]        Codice: {frame.line}")

    def to_bullets(self,items):
        """
        Converte gli oggetti in bullet point con type, risk_level e description.
        Ritorna una lista di stringhe pronte da stampare.
        """
        bullets = []
        for it in items:
            if isinstance(it, dict):
                t = it.get("type", "N/A")
                rl = it.get("risk_level", "N/A")
                desc = it.get("description", "").strip()
                bullets.append(
                    f"[bold blue]Tipo:[/bold blue] {t}\n"
                    f"[bold yellow]Rischio:[/bold yellow] {rl}\n"
                    f"[bold white]Descrizione:[/bold white] {desc}\n"
                )
            else:
                # fallback: se è stringa o altro tipo
                bullets.append(f"[bold blue]Item:[/bold blue] {str(it)}\n")
        return bullets

    def ask_r2ai(self, model_name, query):
        self.initialize_for_model(model_name)
        # Send query to r2ai
        print(f"[R2AI]📦 Querying modello AI {model_name} con prompt \"{query}\" ..(l'operazione può richiedere da 10-120 secondi o più dipende dal modello)...")
        ai_response = self.r2.cmd(f"r2ai -d {query}")
        return ai_response

    def analyze_file_with_r2ai(self, file_path, model_name=None, query="Explain the main function."):
        """
        Analyze a file using radare2 + r2ai plugin.

        :param file_path: Path to the binary file to analyze
        :param model_name: Optional — specify model (e.g., "tinyllama"), else uses default
        :param query: The AI prompt to send after analysis
        :return: AI response as string
        """
        results = {}

        if not os.path.exists(file_path):
            raise FileNotFoundError(f"[R2AI]❌ File not found: {file_path}")

        print("[R2AI]📁 Estrazione metadata e calcolo hashes...")
        metadata = self.get_file_metadata(file_path)
        hashes = self.calculate_hashes(file_path)

        print(f"[R2AI]🗂️ Apertura del file: {file_path}")
        # os.environ["HTTP_PROXY"]="http://127.0.0.1:8888"

        # 1. Apertura con Radare
        print("[R2AI]🔍 Elaborazione con radare2...")
        # Open radare2 in command mode
        # Use flags=['-2'] to avoid ANSI/terminal color issues on Windows
        self.open_file(file_path)

        # 2. Analisi con radare2
        print("[R2AI]📊 Analisi di base...")
        basic_analysis = self.basic_analysis()


        # 3. Rilevamento malware
        print("[R2AI]🦠 Ricerca indicatori malware...")
        suspicious_imports = self.malware_detector.detect_suspicious_imports(
            basic_analysis['imports']
        )
        strings_analysis = self.malware_detector.analyze_strings(
            basic_analysis['strings']
        )
        malware_detection = {
            'suspicious_imports': suspicious_imports,
            'strings_analysis': strings_analysis
        }

        # 4. Analisi avanzata
        print(f"[R2AI]🤖 Analisi con modello AI {model_name}...")
        try:
            for key, prompt in R2AI_PROMPTS.items():
                print(f"[R2AI]Eseguo analisi AI: {key}...")
                raw_response=self.ask_r2ai(model_name, prompt)
                items = self.parse_items(raw_response)
                bullets = self.to_bullets(items)
                if (debug_config==True):
                    print("\n".join(bullets))
                results[key] = ("\n".join(bullets))

        except Exception as e:
            tb = traceback.extract_tb(e.__traceback__)
            print(f"[R2AI]❌ Errore: {e}")
            print("[R2AI]📌 Stack trace completo:")
            for i, frame in enumerate(tb):
                print(f"[R2AI]   [{i}] File: {frame.filename}")
                print(f"[R2AI]        Funzione: {frame.name}")
                print(f"[R2AI]        Riga: {frame.lineno}")
                print(f"[R2AI]        Codice: {frame.line}")


        # 5. Generazione report
        print("[R2AI]📄 Generazione report...\n")
        analysis_data = {
            'metadata': metadata,
            'hashes': hashes,
            'basic_analysis': basic_analysis,
            'malware_detection': malware_detection,
            'ai_analysis': results
        }

        report=self.report_generator.generate_report(analysis_data)
        self.report_generator.export_report(report, "text")


    def close(self):
        """Chiude la connessione radare2"""
        if self.r2:
            self.r2.quit()

def run_scan(file_path,model_name=None, query=None):
    results = {}
    r2ai_a=R2aiAnalyzer()
    r2ai_a.check_r2ai_installed()
    if (model_name is None):
        model_name=R2AI_MODEL_NAME
    try:
        results = r2ai_a.analyze_file_with_r2ai(file_path, model_name, query)

    except Exception as e:
        tb = traceback.extract_tb(e.__traceback__)
        print(f"[R2AI]❌ Errore: {e}")
        print("[R2AI]📌 Stack trace completo:")
        for i, frame in enumerate(tb):
            print(f"[R2AI]   [{i}] File: {frame.filename}")
            print(f"[R2AI]        Funzione: {frame.name}")
            print(f"[R2AI]        Riga: {frame.lineno}")
            print(f"[R2AI]        Codice: {frame.line}")
    finally:
        r2ai_a.close()
    return results

def main():

    if len(sys.argv) < 2:
        print("Usage: python r2aiAnalyzer.py <file_path> [model_name] [query]")
        print("Example: python r2aiAnalyzer.py C:\\Windows\\System32\\notepad.exe")
        sys.exit(1)

    file_path = sys.argv[1]
    model_name = sys.argv[2] if len(sys.argv) > 2 else None
    query = sys.argv[3] if len(sys.argv) > 3 else "Explain the main function."

    try:
        results = run_scan(file_path, model_name, query)
        # Loop per stampare tutte le analisi
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()