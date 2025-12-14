import os
import urllib.parse
from pathlib import Path
from typing import Union, List
from SecModule.common_utils import *
from urllib.parse import urlparse
from SecModule.constants import  PROGRAMMING_EXTENSIONS , LOG_EXTENSIONS, EXECUTABLE_EXTENSIONS, ARCHIVE_EXTENSIONS, DOCUMENT_EXTENSIONS

# --- ESTENSIONI CHE POSSIAMO LEGGERE COME TESTO ---
READABLE_EXTENSIONS = PROGRAMMING_EXTENSIONS | LOG_EXTENSIONS

# --- ESTENSIONI DA NON CRAWLARE/SCARICARE COME TESTO (binari) ---
BINARY_EXTENSIONS = EXECUTABLE_EXTENSIONS | ARCHIVE_EXTENSIONS | DOCUMENT_EXTENSIONS | {'.msi'}


class FileReader:
    def __init__(self):
        self.temp_dir = None

    def _get_temp_dir(self) -> str:
        if self.temp_dir is None:
            import tempfile
            self.temp_dir = tempfile.mkdtemp(prefix="file_reader_")
        return self.temp_dir

    def read_file(self, filepath: str) -> str:
        """Legge un file testuale con fallback su encoding."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"❌ File non trovato: {filepath}")
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return f.read()
        except (UnicodeDecodeError, UnicodeError):
            try:
                with open(filepath, 'r', encoding='latin-1') as f:
                    return f.read()
            except Exception:
                raise ValueError(f"❌ Impossibile decodificare il file: {filepath}")

    def _list_directory(self, dirpath: str) -> List[str]:
        """Elenca solo i file LEGGIBILI (testuali) in una directory (non ricorsivo)."""
        if not os.path.isdir(dirpath):
            raise ValueError(f"Il percorso non è una directory: {dirpath}")

        readable_files = []
        for entry in os.scandir(dirpath):
            if entry.is_file():
                ext = Path(entry.name).suffix.lower()
                if ext in READABLE_EXTENSIONS|BINARY_EXTENSIONS:
                    readable_files.append(entry.path)
                # Altrimenti: salta binari, eseguibili, documenti, ecc.
        return sorted(readable_files)

    def _download_file(self, url: str) -> str:
        import urllib.request
        try:
            with urllib.request.urlopen(url) as response:
                raw = response.read()
                try:
                    return raw.decode('utf-8')
                except UnicodeError:
                    return raw.decode('latin-1')
        except Exception as e:
            raise RuntimeError(f"❌ Download fallito: {url} - {e}")

    def _crawl_and_download(self, base_url: str) -> List[str]:
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            raise ImportError("❌ Installa beautifulsoup4: pip install beautifulsoup4")

        import urllib.request
        from urllib.parse import urljoin, urlparse

        try:
            with urllib.request.urlopen(base_url) as resp:
                soup = BeautifulSoup(resp.read(), 'html.parser')
        except Exception as e:
            raise RuntimeError(f"❌ Impossibile scaricare la pagina: {e}")

        base_netloc = urlparse(base_url).netloc
        downloaded = []
        temp_dir = self._get_temp_dir()

        urls_to_download = set()
        for tag in soup.find_all(['a', 'link', 'script']):
            href = tag.get('href') or tag.get('src')
            if href:
                full = urljoin(base_url, href)
                parsed = urlparse(full)
                if parsed.netloc == base_netloc:
                    ext = Path(parsed.path).suffix.lower()
                    # Scarica SOLO se è leggibile
                    if ext in READABLE_EXTENSIONS:
                        urls_to_download.add(full)

        for url in urls_to_download:
            path = urlparse(url).path
            filename = os.path.basename(path) or f"file_{len(downloaded)}"
            filename = "".join(c for c in filename if c.isalnum() or c in "._-") or "unnamed"
            local_path = os.path.join(temp_dir, filename)

            counter = 1
            orig = local_path
            while os.path.exists(local_path):
                name, ext_ = os.path.splitext(orig)
                local_path = f"{name}_{counter}{ext_}"
                counter += 1

            try:
                urllib.request.urlretrieve(url, local_path)
                downloaded.append(local_path)
            except Exception as e:
                print(f"⚠️  Impossibile scaricare {url}: {e}")

        return downloaded

    # ✅ ENTRY POINT UNIFICATO FINALE
    def load(self, source: str) -> Union[str, List[str]]:
        """
        Gestisce in modo intelligente:
        - File locale leggibile → str
        - Directory locale → List[str] (solo file leggibili)
        - URL di file leggibile → str
        - URL di pagina → List[str] (solo link a file leggibili scaricati)
        """
        parsed = urllib.parse.urlparse(source)

        # 📁📁📁 Gestione percorsi locali (file:// o nessuno schema)
        if not parsed.scheme or parsed.scheme == 'file':
            path = parsed.path if parsed.scheme == 'file' else source
            if not os.path.exists(path):
                raise FileNotFoundError(f"❌ Percorso non trovato: {path}")

            if os.path.isdir(path):
                return self._list_directory(path)
            elif os.path.isfile(path):
                ext = Path(path).suffix.lower()
                if ext in READABLE_EXTENSIONS|BINARY_EXTENSIONS :
                    return self.read_file(path)
                else:
                    raise ValueError(f"❌ Estensione non supportata per la lettura: {ext} (file: {path})")
            else:
                raise ValueError(f"❌ Percorso non valido: {path}")

        # 🌐🌐🌐 Gestione URL
        if parsed.scheme in ('http', 'https'):
            ext = Path(parsed.path).suffix.lower()
            if ext in READABLE_EXTENSIONS|BINARY_EXTENSIONS:
                return self._download_file(source)
            else:
                # Nessuna estensione o estensione sconosciuta → trattala come pagina da crawler
                return self._crawl_and_download(source)

        raise ValueError(f"❌ Schema non supportato: {parsed.scheme}")

def get_filename(path_or_url):
    # Prova prima come URL
    parsed = urlparse(path_or_url)
    if parsed.scheme in ('http', 'https'):
        # Estrai il nome dal path dell'URL
        return os.path.abspath(parsed.path)
    else:
        # Altrimenti è un percorso locale
        return os.path.abspath(path_or_url)

def main():
    reader = FileReader()

    # Legge PDF locale
    text = reader.load("common_utils.py")  # → str (testo estratto)
    print(f"text readed. Length:{len(text)}")
    # Legge EXE locale
    strings = reader.load("../artifact/clamav-1.4.3.win.x64.msi")  # → str (stringhe ASCII)

    # Scarica e legge PDF remoto
    text = reader.load("https://pdfobject.com/pdf/sample.pdf")
    print(f"pdf readed. Length:{len(text)}")

    # Scarica e legge PDF remoto
    text = reader.load("../samples/test.js")
    print(f"js readed. Length:{len(text)}")

    text = reader.load("https://file-examples.com/wp-content/storage/2017/02/index.html")
    print(f"html readed. Length:{len(text)}")

    # Directory con PDF ed EXE
    files = reader.load("../samples/")  # → ['a.exe', 'b.pdf'] (solo se leggibili)
    for f in files:
        print(get_filename(f))

    # Crawling che include link a PDF/EXE
    downloaded = reader.load("https://file-examples.com/index.php/text-files-and-archives-download/")
    for d in downloaded:
        print(get_filename(d))

if __name__ == "__main__":
    main()