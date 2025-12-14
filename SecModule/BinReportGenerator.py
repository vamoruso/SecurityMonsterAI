import json
import datetime
from dataclasses import dataclass
from typing import Dict, List

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table


@dataclass
class AnalysisReport:
    file_metadata: Dict
    hashes: Dict[str, str]
    basic_analysis: Dict
    malware_detection: Dict
    ai_analysis: Dict
    timestamp: str
    risk_score: float

class BinReportGenerator:
    def __init__(self):
        self.reports = []
    
    def generate_report(self, analysis_data: Dict) -> AnalysisReport:
        """Genera un report completo dell'analisi"""
        risk_score = self._calculate_risk_score(analysis_data)
        
        report = AnalysisReport(
            file_metadata=analysis_data['metadata'],
            hashes=analysis_data['hashes'],
            basic_analysis=analysis_data['basic_analysis'],
            malware_detection=analysis_data['malware_detection'],
            ai_analysis=analysis_data['ai_analysis'],
            timestamp=datetime.datetime.now().isoformat(),
            risk_score=risk_score
        )
        
        self.reports.append(report)
        return report
    
    def _calculate_risk_score(self, analysis_data: Dict) -> float:
        """Calcola un punteggio di rischio basato sulle analisi"""
        score = 0.0
        
        # Logica per calcolare il rischio
        malware_findings = analysis_data['malware_detection']
        if malware_findings['suspicious_imports']:
            score += len(malware_findings['suspicious_imports']) * 0.1
        
        if malware_findings['strings_analysis']['suspicious_urls']:
            score += len(malware_findings['strings_analysis']['suspicious_urls']) * 0.2
        
        return min(score, 1.0)
    
    def export_report(self, report: AnalysisReport, format: str = 'json') -> str:
        """Esporta il report in vari formati"""
        if format == 'json':
            return json.dumps(report.__dict__, indent=2)
        elif format == 'text':
            return self._format_text_report(report)
        else:
            report_text=self._format_text_report(report)
            #print(report_text)
    
    def _format_text_report(self, report: AnalysisReport) -> str:
        """Formatta il report in testo semplice"""
        console = Console()
        # === Tabella Metadati ===
        meta_table = Table(show_header=False, box=box.SIMPLE)
        meta_table.add_row("[bold]File:[/bold]", report.file_metadata['path'])
        meta_table.add_row("[bold]Shannon Entropy:[/bold]", f"{report.file_metadata['entropy']:.4f}")
        meta_table.add_row("[bold]Timestamp:[/bold]", report.timestamp)
       # meta_table.add_row("[bold]Risk Score:[/bold]", f"[bold yellow]{report.risk_score:.2f}/10.0[/bold yellow]")

        # === Tabella Hash ===
        hash_table = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE)
        hash_table.add_column("Tipo", style="dim")
        hash_table.add_column("Valore")
        hash_table.add_row("MD5", report.hashes['md5'])
        hash_table.add_row("SHA1", report.hashes['sha1'])
        hash_table.add_row("SHA256", report.hashes['sha256'])

        # === Tabella Malware Detection ===
        malware_table = Table(title="Sommario Analisi Malware Detector", show_header=True, header_style="bold red", box=box.SIMPLE)
        malware_table.add_column("Indicatori", style="bold")
        malware_table.add_column("Conteggio", justify="left")
        # Import sospetti
        imports = report.malware_detection['suspicious_imports']
        malware_table.add_row(
            "Import sospetti",
            f"{len(imports)} ({', '.join(imports)})" if imports else "0"
        )

        # URLs sospetti
        urls = report.malware_detection['strings_analysis']['suspicious_urls']
        malware_table.add_row(
            "URLs sospetti",
            f"{len(urls)} ({', '.join(urls)})" if urls else "0"
        )

        # Indirizzi IP
        ips = report.malware_detection['strings_analysis']['ip_addresses']
        malware_table.add_row(
            "Indirizzi IP",
            f"{len(ips)} ({', '.join(ips)})" if ips else "0"
        )
        # === Unisci tutto in un unico pannello verticale ===
        combined_table = Table.grid(padding=(0, 2))
        combined_table.add_row(meta_table)
        combined_table.add_row("")
        combined_table.add_row(hash_table)
        combined_table.add_row("")
        combined_table.add_row(malware_table)
        ai_table = None
        if (len(report.ai_analysis.items()) > 0):
            ai_table = Table(title="Sommario Analisi con R2AI", show_header=True, header_style="bold magenta", box=box.SIMPLE)
            ai_table.add_column("Tipo prompt", width=20)
            ai_table.add_column("Risposta", style="dim")
            for key, analysis in report.ai_analysis.items():
                # Mostra la keyword come titolo e un estratto dell'analisi
                clean_key = key.replace("_", " ").capitalize()
                snippet = (analysis[:1000] + "...") if len(analysis) > 5000 else analysis
                ai_table.add_row(clean_key, snippet)
            combined_table.add_row("")
            combined_table.add_row(ai_table)

        console.print(Panel(
            combined_table,
            title="[bold blue]Malware Analysis Report[/bold blue]",
            border_style="blue",
            expand=False
        ))


        return str(meta_table)+'\n'+str(hash_table)+'\n'+str(malware_table)+'\n'+str(ai_table)

    def _summarize_ai_analysis(self, ai_analysis: Dict[str, str]) -> str:
        """Crea un sommario delle analisi AI con keyword"""
        summary = []
        for key, analysis in ai_analysis.items():
            # Mostra la keyword come titolo e un estratto dell'analisi
            clean_key = key.replace("_", " ").capitalize()
            snippet = (analysis[:100] + "...") if len(analysis) > 100 else analysis
            summary.append(f"{clean_key}: {snippet}")
        return "\n".join(summary)