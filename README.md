## Security Monster AI

###

### Questo repository è collegato al progetto software per la tesi di laurea magistrale di Vincenzo Amoruso dell'AA 2025/26 della **Universitas Mercatorum**
### Corso di laurea in : ***Cybersecurity LM-66***
### Relatore : ***Prof. Davide Berardi***
### Insegnamento di : ***Cybersecuirty***
### Titolo della tesi : ***Applicazione di Modelli Linguistici Locali nell’Analisi Predittiva delle Minacce Informatiche: Un Approccio basato sull’Intelligenza Artificiale***
### Obiettivo: ***Il progetto applica con esempi pratici alla Cybersecuiry alcune delle potenzialità della intelligenza artificiale.***

## Preparazione ambiente server Python

### - Installare Python, scaricabile dal seguente link (Abbiamo selezionato la versione Windows a 64bit)
[https://www.python.org/ftp/python/3.10.4/python-3.10.4-amd64.exe](https://www.python.org/ftp/python/3.10.4/python-3.10.4-amd64.exe)
### - Creare l'ambiente virtuale Python del server con il comando
    python -m venv D:\Users\vincw\SecurityMonster
### - Attivare l'ambiente virtuale 
    D:\Users\vincw\SecurityMonster\Scripts\activate 
### - Copiare tutti i files scaricati dal repository remoto GitHub nella cartella dell'ambiente virtuale locale.

### - Nell'ambiente virtuale *(venv) D:\Users\vincw\SecurityMonster*  eseguire il comando per installare tutti i pacchetti necessari
    pip install requirements.txt 

> [!NOTE]
> Il server ollma deve essere in ascolto sulla porta 11434 all'indirizzo https://localhost:11434 <br/>
> Il server ClamAV deve essere in ascolto sulla porta 3310 all'indirizzo https://localhost:3310 


## Schema progetto e tecnologie

###

![Schema](documentation/SchemaArchitteturaTesi.png)

<div align="left">
 <img width="12" />
  <img src="https://cdn.jsdelivr.net/gh/devicons/devicon/icons/python/python-original.svg" height="40" alt="python logo"  />
</div>


## Screenshots e video di test

### SecurityMonster analisi codice sorgente
    
<table>
<tr>
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/source/screen1_source_analisi.png" style="width: 50%; height: 50%" /> </td>
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/source/screen2_source_analisi.png" style="width: 50%; height: 50%" /> </td>
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/source/screen3_source_analisi.png" style="width: 50%; height: 50%" /> </td>
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/source/screen4_source_analisi.png" style="width: 50%; height: 50%" /> </td>
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/source/screen5_source_analisi.png" style="width: 50%; height: 50%" /> </td>
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/source/screen6_source_analisi.png" style="width: 50%; height: 50%" /> </td>
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/source/screen7_source_analisi_sito.png" style="width: 50%; height: 50%" /> </td>
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/source/screen9_source_analisi_sito.png" style="width: 50%; height: 50%" /> </td>
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/source/screen10_source_analisi_sito.png" style="width: 50%; height: 50%" /> </td>
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/source/screen11_source_analisi_sito.png" style="width: 50%; height: 50%" /> </td>
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/source/screen12_source_analisi_sito.png" style="width: 50%; height: 50%" /> </td>
</tr>  
     <tr>
      <td colspan=11>[Video](https://youtu.be/9S8fvFy-tFI)</td> 
   </tr> 
</table>
    
### SecurityMonster analisi logs

<table>
   <tr>
   <td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/logs/analisi_log_screen1_avvio.png" style="width: 50%; height: 50%" /> </td>
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/logs/analisi_log_screen2_01_Reconnisance.png" style="width: 50%; height: 50%" /> </td>
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/logs/analisi_log_screen3_02_Resource.png" style="width: 50%; height: 50%" /> </td>
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/logs/analisi_log_screen4_03_Initial_Access.png" style="width: 50%; height: 50%" /> </td>
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/logs/analisi_log_screen5_04_PowerShell_script_exectuion.png" style="width: 50%; height: 50%" /> </td>
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/logs/analisi_log_screen6_05_Persistence.png" style="width: 50%; height: 50%" /> </td>
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/logs/analisi_log_screen7_06_Privilege_escalation.png" style="width: 50%; height: 50%" /> </td>
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/logs/analisi_log_screen8_07_Defence_Evasion.png" style="width: 50%; height: 50%" /> </td>
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/logs/analisi_log_screen9_08_Credential_Access.png" style="width: 50%; height: 50%" /> </td>
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/logs/analisi_log_screen10_09_Discovery.png" style="width: 50%; height: 50%" /> </td>
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/logs/analisi_log_screen11_10_Lateral_movement.png" style="width: 50%; height: 50%" /> </td>
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/logs/analisi_log_screen12_11_Collection.png" style="width: 50%; height: 50%" /> </td>
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/logs/analisi_log_screen13_12_Command_and_control.png" style="width: 50%; height: 50%" /> </td>
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/logs/analisi_log_screen14_13_Exfiltration.png" style="width: 50%; height: 50%" /> </td>
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/logs/analisi_log_screen15_14_Impact.png" style="width: 50%; height: 50%" /> </td>
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/logs/analisi_log_screen16_riepilogo.png" style="width: 50%; height: 50%" /> </td>
   </tr>
   <tr>
      <td colspan=16>[Video](https://youtu.be/PZYo-wV8GzY)</td> 
   </tr> 
</table>  
    
### SecurityMonster analisi binary ed eseguibili
<table>
<tr>
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/binary/01_avvio_eicar_pe.png" style="width: 50%; height: 50%"/> </td> 
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/binary/02_clamav_eicar_pe.png" style="width: 50%; height: 50%"/> </td> 
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/binary/03_MalwareDectector_eicar_pe.png" style="width: 50%; height: 50%"/> </td> 
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/binary/03_r2ai_eicar_pe.png" style="width: 50%; height: 50%"/> </td> 
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/binary/03_yara_eicar_pe.png" style="width: 50%; height: 50%"/> </td> 
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/binary/04_lief_eicar_pe.png" style="width: 50%; height: 50%"/> </td> 
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/binary/05_lief_analsi_entropia_ia_eicar_pe.png" style="width: 50%; height: 50%"/> </td> 
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/binary/06b_radare_prompt_eicar_pe.png" style="width: 50%; height: 50%"/> </td> 
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/binary/06_radare_analsi_ia_eicar_pe.png" style="width: 50%; height: 50%"/> </td> 
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/binary/07_radare2_malwarereport1_ia_eicar_pe.png" style="width: 50%; height: 50%"/> </td> 
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/binary/08_radare2_malware_indicators_ia_eicar_pe.png" style="width: 50%; height: 50%"/> </td> 
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/binary/09_radare2_suspicious_api_ia_eicar_pe.png" style="width: 50%; height: 50%"/> </td> 
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/binary/10_radare2_network_c2_api_ia_eicar_pe.png" style="width: 50%; height: 50%"/> </td> 
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/binary/11_radare2_obfuscation_ia_eicar_pe.png" style="width: 50%; height: 50%"/> </td> 
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/binary/13_PackerLikeFolder.png" style="width: 50%; height: 50%"/> </td> 
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/binary/13_PackerMalwareDetector.png" style="width: 50%; height: 50%"/> </td> 
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/binary/13_PackerR2ai.png" style="width: 50%; height: 50%"/> </td> 
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/binary/13_Packer_a.png" style="width: 50%; height: 50%"/> </td> 
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/binary/14_EvasionLief.png" style="width: 50%; height: 50%"/> </td> 
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/binary/14_EvasionLief_AI.png" style="width: 50%; height: 50%"/> </td> 
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/binary/14_EvasionLikeFolder.png" style="width: 50%; height: 50%"/> </td> 
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/binary/14_EvasionMalwareDetector.png" style="width: 50%; height: 50%"/> </td> 
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/binary/14_EvasionR2ai.png" style="width: 50%; height: 50%"/> </td> 
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/binary/14_Evasion_dll.png" style="width: 50%; height: 50%"/> </td> 
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/binary/15_RansomewareDetector.png" style="width: 50%; height: 50%"/> </td> 
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/binary/15_RansomewareFolder.png" style="width: 50%; height: 50%"/> </td> 
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/binary/15_RansomewareLief.png" style="width: 50%; height: 50%"/> </td> 
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/binary/15_RansomewareLief_AI.png" style="width: 50%; height: 50%"/> </td> 
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/binary/15_RansomewareR2ai.png" style="width: 50%; height: 50%"/> </td> 
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/binary/15_Ransomeware_so.png" style="width: 50%; height: 50%"/> </td> 
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/binary/16_TrojanDetector.png" style="width: 50%; height: 50%"/> </td> 
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/binary/16_TrojanFolder.png" style="width: 50%; height: 50%"/> </td> 
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/binary/16_TrojanLike_o.png" style="width: 50%; height: 50%"/> </td> 
<td><img src="https://github.com/vamoruso/SecurityMonsterAI/blob/main/screenshoots/binary/16_TrojanR2ai.png" style="width: 50%; height: 50%"/> </td> 
</tr>  
     <tr>
      <td colspan=34>[Video](https://youtu.be/XBB3AnkUHHY)</td> 
   </tr> 
</table>   

###

## Credits

### Media

• Tutti gli screenshot del codice utilizzato in questo README sono stati realizzati da me su dispostivo Windows 11 a 64bit 32GB RAM Processore	Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz, 2208 Mhz, 6 core, 12 processori logici

### Ringraziamenti

* [Radare2](https://github.com/radareorg/radare2).
* [R2ai](https://github.com/radareorg/r2ai)


---
###

<h2 align="left">Vincenzo Amoruso <cite>2025</cite></h2>


![Markdown](https://img.shields.io/badge/markdown-%23000000.svg?style=flat=markdown&logoColor=white) ![GitHub contributors](https://img.shields.io/github/contributors/vamoruso/SecurityMonster?style=flat) ![GitHub last commit](https://img.shields.io/github/last-commit/vamoruso/SecurityMonster?style=flat)  ![GitHub Repo stars](https://img.shields.io/github/stars/vamoruso/SecurityMonster?style=social)  



