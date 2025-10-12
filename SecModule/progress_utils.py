import time
import threading
import itertools
import sys
from tqdm import tqdm

try:
    from alive_progress import alive_bar
    HAS_ALIVE = True
except ImportError:
    HAS_ALIVE = False


class ProgressManager:
    def __init__(self):
        self._stop_flag = False
        self._thread = None

    def start_tqdm_loop(self, desc="Caricamento"):
        def _run():
            with tqdm(total=100, desc=desc, bar_format="{l_bar}{bar}| {elapsed}") as pbar:
                while not self._stop_flag:
                    pbar.update(1)
                    time.sleep(0.1)
                    if pbar.n >= 100:
                        pbar.n = 0
                        pbar.refresh()
        self._launch(_run)

    def start_alive_bar(self, spinner='dots_waves', bar='classic'):
        if not HAS_ALIVE:
            print("⚠️ Il pacchetto 'alive-progress' non è installato.")
            return

        def _run():
            with alive_bar(0, spinner=spinner, bar=bar) as bar:
                while not self._stop_flag:
                    time.sleep(0.1)
                    bar()
        self._launch(_run)

    def start_spinner(self, charset='braille'):
        spinner_sets = {
            'classic': ['|', '/', '-', '\\'],
            'braille': ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏'],
            'dots': ['⠁','⠂','⠄','⡀','⢀','⠠','⠐','⠈']
        }
        chars = spinner_sets.get(charset, spinner_sets['classic'])

        def _run():
            for c in itertools.cycle(chars):
                if self._stop_flag:
                    break
                sys.stdout.write(f'\rCaricamento {c}')
                sys.stdout.flush()
                time.sleep(0.1)
            sys.stdout.write('\rFatto!     \n')

        self._launch(_run)

    def _launch(self, target):
        self._stop_flag = False
        self._thread = threading.Thread(target=target)
        self._thread.start()

    def stop(self):
        self._stop_flag = True
        if self._thread:
            self._thread.join()
            self._thread = None


# 🧪 Esempio d’uso
if __name__ == "__main__":
    pm = ProgressManager()

    print("▶ Avvio spinner braille...")
    pm.start_spinner(charset='braille')
    time.sleep(5)
    pm.stop()

    print("▶ Avvio barra tqdm...")
    pm.start_tqdm_loop()
    time.sleep(5)
    pm.stop()

    if HAS_ALIVE:
        print("▶ Avvio alive-progress...")
        pm.start_alive_bar()
        time.sleep(5)
        pm.stop()
