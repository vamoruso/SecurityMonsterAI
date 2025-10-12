import time
import json
from typing import Dict, Any
import ollama

class ai_model_manager:
    def __init__(self):
        # Dizionario per accumulare i tempi: {modello: [tempo1, tempo2, ...]}
        self.timing_data: Dict[str, list] = {}

    def query_model(self, model: str, prompt: str) -> Dict[str, Any]:
        """Interroga un modello Ollama e restituisce la risposta parsata come JSON."""
        start_time = time.perf_counter()  # Avvia il cronometro

        try:
            response = ollama.chat(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                options={"temperature": 0.1}
            )

            raw_response = response['message']['content'].strip()

            # Pulizia del markdown JSON
            if raw_response.startswith("```json"):
                raw_response = raw_response[7:].strip()
            if raw_response.endswith("```"):
                raw_response = raw_response[:-3].strip()

            result = json.loads(raw_response)

        except Exception as e:
            # Gestione errori: restituisci un risultato vuoto o con errore
            result = {"error": str(e)}

        finally:
            # Fermiamo il cronometro ANCHE in caso di errore
            elapsed_time = time.perf_counter() - start_time

            # Memorizziamo il tempo per il modello
            if model not in self.timing_data:
                self.timing_data[model] = []
            self.timing_data[model].append(elapsed_time)

        return result

    def get_timing_stats(self) -> Dict[str, Dict[str, float]]:
        """Restituisce statistiche sui tempi di elaborazione per modello."""
        stats = {}
        for model, times in self.timing_data.items():
            stats[model] = {
                "chiamate": len(times),
                "totale_sec": sum(times),
                "media_sec": sum(times) / len(times),
                "min_sec": min(times),
                "max_sec": max(times)
            }
        return stats

    def print_timing_report(self):
        """Stampa un report leggibile dei tempi."""
        from rich.table import Table
        from rich.console import Console

        table = Table(title="⏱️ Tempi di Elaborazione per Modello", show_header=True)
        table.add_column("Modello", style="cyan")
        table.add_column("Chiamate", justify="right")
        table.add_column("Media (s)", justify="right")
        table.add_column("Min (s)", justify="right")
        table.add_column("Max (s)", justify="right")
        table.add_column("Totale (s)", justify="right")

        for model, stats in self.get_timing_stats().items():
            table.add_row(
                model,
                str(stats["chiamate"]),
                f"{stats['media_sec']:.3f}",
                f"{stats['min_sec']:.3f}",
                f"{stats['max_sec']:.3f}",
                f"{stats['totale_sec']:.3f}"
            )

        Console().print(table)