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

from SecModule import common_utils, lief_analyzer, clamav_analyzer, r2ai_analyzer, yara_analyzer
from SecModule.ai_model_manager import ai_model_manager
from SecModule.common_utils import is_programming_file, pad_to_80, is_executable_file
from SecModule.constants import SOURCE_CODE_MODELS, SOURCE_CODE_PROMPT_TEMPLATE
from SecModule.file_reader import FileReader
from SecModule.progress_utils import ProgressManager
from debug_config import DEBUG_MODE


class BinaryCodeAnalyzer:
    def __init__(self, models: List[str] = None):
        self.models = models or SOURCE_CODE_MODELS
        self.aimodelmanager=ai_model_manager()
        self.pm = ProgressManager()

def run_scan(filepath_or_url):
    analyzer = BinaryCodeAnalyzer()
    filereader= FileReader()

    print(f"[+] Analisi con IA del file binario di {filepath_or_url}")
    result=filereader.load(filepath_or_url)

    files_list=[]
    if isinstance(result, str):
        files_list.append(filepath_or_url)
    else:
        files_list=result

    report_file = common_utils.normalizza_nome_log(filepath_or_url)

    try:
            for filepath in files_list:
                if (is_executable_file(filepath)):
                    print(f"[+] File letto: {filepath}")
                    clamav_analyzer.run_scan(filepath)
                    yara_analyzer.run_scan(filepath,'./yara_def/malware_index.yar')
                    lief_analyzer.run_scan(filepath)
                    r2ai_analyzer.run_scan(filepath)
                    #report = ""
                    #with open(report_file, "a", encoding="utf-8") as f:
                    #    f.write(report+"\n")
                else:
                    print(f"[+] Il file {filepath} non è eseguibile.")
                # Salva report su file
            print(f"\n✅ Report salvato in: {report_file}")
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