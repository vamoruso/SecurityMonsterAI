from pygments.util import ClassNotFound
from pygments.lexers import get_lexer_for_filename
from pygments.util import ClassNotFound
import magic
import os
import zipfile
import datetime
import shutil


log_file = 'logs/scan_log.txt'
quarantine_folder = 'quarantine'

# Estensioni di codice sorgente
PROGRAMMING_EXTENSIONS = {
    '.py', '.js', '.ts', '.java', '.bat', '.c', '.cmd', '.cpp', '.cs', '.go', '.rs',
    '.rb', '.php', '.swift', '.kt', '.scala', '.pl', '.sh', '.bash',
    '.ps1', '.m', '.sql', '.htm', '.html', '.css', '.scss', '.vue', '.jsx',
    '.tsx', '.dart', '.lua', '.r', '.jl', '.hs', '.erl', '.ex', '.fs',
    '.yaml', '.yml', '.json', '.xml', '.toml', '.ini', '.cfg', '.conf'
}

# Estensioni di eseguibili, librerie, archivi
EXECUTABLE_EXTENSIONS = {
    '.exe', '.dll', '.so', '.dylib', '.bin', '.elf', '.com', '.sys', '.scr',
    '.msi', '.app', '.out', '.ko', '.lib', '.a', '.o'
}

ARCHIVE_EXTENSIONS = {
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.tgz', '.tbz2',
    '.zst', '.cab', '.iso', '.img', '.dmg', '.apk', '.jar', '.war', '.ear'
}

DOCUMENT_EXTENSIONS = {
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt', '.ods', '.odp'
}

LOG_EXTENSIONS = {
    '.log','.txt','.pcap','.evtx'
}


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

if __name__ == "__main__":
    test_files = [
        "script.py",
        "malware.exe",
        "library.dll",
        "data.zip",
        "document.pdf",
        "unknown.bin"
    ]

    for f in test_files:
        if os.path.exists(f):
            info = identify_file(f)
            print(f"\n📁 {f}")
            print(f"   Tipo: {info['file_type']}")
            print(f"   Source: {info['is_source_code']}, Exec: {info['is_executable']}, "
                  f"Arch: {info['is_archive']}, Doc: {info['is_document']}")
            print(f"   Descrizione: {info['description'][:80]}...")
        else:
            print(f"⚠️ {f} non trovato")