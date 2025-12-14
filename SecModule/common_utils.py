from pygments.lexers import get_lexer_for_filename
from pygments.util import ClassNotFound
import magic
import os
import zipfile
import datetime
import shutil
import re
import urllib.parse
from datetime import datetime

from SecModule.constants import PROGRAMMING_EXTENSIONS, EXECUTABLE_EXTENSIONS, ARCHIVE_EXTENSIONS, DOCUMENT_EXTENSIONS, \
    LOG_EXTENSIONS

log_file = 'logs/scan_log.txt'
quarantine_folder = 'quarantine'



def identify_file(filename):
    """
    Identifica il tipo di file.
    Restituisce un dizionario con:
    - is_source_code: bool
    - is_executable: bool
    - is_archive: bool
    - is_document: bool
    - file_type: str (descrizione)
    - mime_type: str
    - description: str (da libmagic)
    """

    result = {
        "is_source_code": False,
        "is_executable": False,
        "is_archive": False,
        "is_document": False,
        "is_log": False,
        "file_type": "unknown",
        "mime_type": "unknown",
        "description": ""
    }

    if not os.path.exists(filename):
        return result

    # Estrai estensione
    _, ext = os.path.splitext(filename)
    ext = ext.lower()

    # Prova con python-magic (obbligatorio per riconoscimento affidabile)
    try:
        mime_type = magic.from_file(filename, mime=True)
        description = magic.from_file(filename).lower()
        result["mime_type"] = mime_type
        result["description"] = description
    except Exception as e:
        print(f"[Errore Magic] {e}")
        return result

    # 1. Controlla se è codice sorgente
    if ext in PROGRAMMING_EXTENSIONS:
        try:
            get_lexer_for_filename(filename)
            result["is_source_code"] = True
            result["file_type"] = "source_code"
            return result
        except ClassNotFound:
            pass  # Pygments non lo riconosce → passa a magic

    # Usa magic per riconoscere codice sorgente (fallback)
    if mime_type.startswith("text/") and not (
        "executable" in description or
        "archive" in description or
        "document" in description
    ):
        source_keywords = [
            'source', 'script', 'code', 'shell script', 'python script',
            'javascript', 'java', 'c++', 'c#', 'ruby', 'php', 'perl', 'lua',
            'swift', 'kotlin', 'rust', 'html', 'css', 'sql', 'makefile',
            'yaml', 'json', 'xml', 'batch', 'powershell'
        ]
        if any(kw in description for kw in source_keywords):
            result["is_source_code"] = True
            result["file_type"] = "source_code"
            return result

    # 2. Controlla se è eseguibile/libreria
    if ext in EXECUTABLE_EXTENSIONS or any(kw in description for kw in [
        'executable', 'pe32', 'pe32+', 'elf', 'shared object', 'ms-dos',
        'com executable', 'mach-o', 'dynamic lib', 'dll', 'msi installer'
    ]):
        result["is_executable"] = True
        result["file_type"] = "executable"
        return result

    # 3. Controlla se è archivio
    if ext in ARCHIVE_EXTENSIONS or any(kw in description for kw in [
        'zip archive', 'rar archive', '7-zip', 'tar archive', 'gzip compressed',
        'bzip2 compressed', 'xz compressed', 'iso 9660', 'dmg', 'android package',
        'java archive', 'jar', 'winrar'
    ]):
        result["is_archive"] = True
        result["file_type"] = "archive"
        return result

    # 4. Controlla se è documento
    if ext in DOCUMENT_EXTENSIONS or any(kw in description for kw in [
        'pdf document', 'microsoft word', 'excel', 'powerpoint', 'open document',
        'rtf', 'rich text'
    ]):

        result["is_document"] = True
        result["file_type"] = "document"
        return result

    # 5. Log
    if ext in LOG_EXTENSIONS or any(kw in description for kw in [
        'text log', 'microsoft word', 'net packet', 'windows event log'
    ]):
        result["is_log"] = True
        result["file_type"] = "log"
        return result

    return result


def is_programming_file(filename):

    return identify_file(filename)["is_source_code"]

def is_executable_file(filename):
    return identify_file(filename)["is_executable"]

def is_archive_file(filename):
    return identify_file(filename)["is_archive"]

def is_document_file(filename):
    return identify_file(filename)["is_document"]

def is_log_file(filename):
    return identify_file(filename)["is_log"]

def get_file_type(filename):
    return identify_file(filename)["file_type"]

def is_pcap(filename):
    try:
        mime= identify_file(filename)["mime_type"]
        desc = identify_file(filename)["description"]

        # Metodo 1: controllo sul MIME type (più affidabile)
        if mime in ('application/vnd.tcpdump.pcap', 'application/pcap'):
            return True

        # Metodo 2: fallback su descrizione testuale (caso comune se mime=False o libmagic vecchia)
        desc_lower = desc.lower()
        pcap_keywords = [
            'tcpdump capture file',
            'pcap capture',
            'libpcap capture',
            'wireshark/tcpdump/... - libpcap',
            'pcap-ng capture file',  # per pcapng
            'pcapng',
        ]
        return any(kw in desc_lower for kw in pcap_keywords)
    except Exception as e:
        # Gestione errori (file non esistente, permessi, ecc.)
        print(f"[!] Errore su {filename}: {e}")
    return False

def zip_extraction(zip_path, dest_folder):
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(dest_folder)

# ✅ Funzione di logging
def log_event(message):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(log_file, 'a') as f:
        f.write(f"[{timestamp}] {message}\n")

# ✅ Funzione di quarantena
def quarantine(file_path):
    if not os.path.exists(quarantine_folder):
        os.makedirs(quarantine_folder)
    shutil.move(file_path, os.path.join(quarantine_folder, os.path.basename(file_path)))
    log_event(f"File spostato in quarantena: {file_path}")


def normalizza_nome_log(input_path_or_url: str, prefix: str = "", suffix: str = "", estensione: str = ".log") -> str:
    """
    Genera un nome file normalizzato per log, basato su un path, file o URL.
    Aggiunge data e ora al nome.
    """
    # Estrai nome base da URL o path
    if input_path_or_url.startswith(("http://", "https://")):
        parsed = urllib.parse.urlparse(input_path_or_url)
        base = os.path.basename(parsed.path) or parsed.netloc
    else:
        base = os.path.basename(input_path_or_url.rstrip("/"))

    # Rimuovi estensione e caratteri non validi
    base = os.path.splitext(base)[0]
    base = re.sub(r"[^\w\-]+", "_", base)  # Solo lettere, numeri, underscore, trattini

    # Timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Componi nome finale
    nome = f"{prefix}{base}_{timestamp}{suffix}{estensione}"
    return nome

def pad_to_80(text):
    return text + ' ' * (80 - len(text)) if len(text) < 80 else text[:80]

if __name__ == "__main__":
    test_files = [
        "../samples/malicious_traffic.pcap",
        "../samples/log/mitre_list/03_Initial_Access.pcap"

        #"script.py",
        #"malware.exe",
        #"library.dll",
        #"data.zip",
        #"document.pdf",
        #"unknown.bin"

    ]

    for f in test_files:
        if os.path.exists(f):
            info = identify_file(f)
            print(f"\n📁 {f}")
            print(f"   Tipo: {info['file_type']}")
            print(f"   Source: {info['is_source_code']}, Exec: {info['is_executable']}, "
                  f"Arch: {info['is_archive']}, Doc: {info['is_document']}, log: {info['is_log']}")
            print(f"   Descrizione: {info['description'][:80]}...")
            if (is_pcap(f)):
                print(f"   è PCAP")
        else:
            print(f"⚠️ {f} non trovato")