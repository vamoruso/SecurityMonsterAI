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
<td><img src="https://github.com/vamoruso/SecurityMonster/blob/main/screenshoots/source/screen1_source_analisi.png" style="width: 50%; height: 50%" /> </td>
<td><img src="https://github.com/vamoruso/SecurityMonster/blob/main/screenshoots/source/screen2_source_analisi.png" style="width: 50%; height: 50%" /> </td>
<td><img src="https://github.com/vamoruso/SecurityMonster/blob/main/screenshoots/source/screen3_source_analisi.png" style="width: 50%; height: 50%" /> </td>
<td><img src="https://github.com/vamoruso/SecurityMonster/blob/main/screenshoots/source/screen4_source_analisi.png" style="width: 50%; height: 50%" /> </td>
<td><img src="https://github.com/vamoruso/SecurityMonster/blob/main/screenshoots/source/screen5_source_analisi.png" style="width: 50%; height: 50%" /> </td>
<td><img src="https://github.com/vamoruso/SecurityMonster/blob/main/screenshoots/source/screen6_source_analisi.png" style="width: 50%; height: 50%" /> </td>
<td><img src="https://github.com/vamoruso/SecurityMonster/blob/main/screenshoots/source/screen7_source_analisi_sito.png" style="width: 50%; height: 50%" /> </td>
<td><img src="https://github.com/vamoruso/SecurityMonster/blob/main/screenshoots/source/screen9_source_analisi_sito.png" style="width: 50%; height: 50%" /> </td>
<td><img src="https://github.com/vamoruso/SecurityMonster/blob/main/screenshoots/source/screen10_source_analisi_sito.png" style="width: 50%; height: 50%" /> </td>
<td><img src="https://github.com/vamoruso/SecurityMonster/blob/main/screenshoots/source/screen11_source_analisi_sito.png" style="width: 50%; height: 50%" /> </td>
<td><img src="https://github.com/vamoruso/SecurityMonster/blob/main/screenshoots/source/screen12_source_analisi_sito.png" style="width: 50%; height: 50%" /> </td>
</tr>  
     <tr>
      <td colspan=11>[Video](https://youtu.be/9S8fvFy-tFI)</td> 
   </tr> 
</table>
    
### SecurityMonster analisi logs

<table>
   <tr>
    <td><img src="https://github.com/vamoruso/SecurityMonster/blob/main/screenshots/Chatbot/Chatbot_screen1.png" style="width: 50%; height: 50%"/> </td>
    <td><img src="https://github.com/vamoruso/SecurityMonster/blob/main/screenshots/Chatbot/Chatbot_screen2.png" style="width: 50%; height: 50%"/> </td>
    <td><img src="https://github.com/vamoruso/SecurityMonster/blob/main/screenshots/Chatbot/Chatbot_screen3.png" style="width: 50%; height: 50%"/> </td>
    <td><img src="https://github.com/vamoruso/SecurityMonster/blob/main/screenshots/Chatbot/Chatbot_screen4.png" style="width: 50%; height: 50%"/> </td>
    <td><img src="https://github.com/vamoruso/SecurityMonster/blob/main/screenshots/Chatbot/Chatbot_screen5.png" style="width: 50%; height: 50%"/> </td>
   </tr>
   <tr>
      <td colspan=5>[Video](https://youtu.be/PZYo-wV8GzY)</td> 
   </tr> 
</table>  
    
### SecurityMonster analisi binary ed eseguibili
<table>
<tr>
<td><img src="https://github.com/vamoruso/SecurityMonster/blob/main/screenshots/absences_vocal_command/AssenzeDaComandoVocale_screen1.png" style="width: 50%; height: 50%"/> </td>
<td><img src="https://github.com/vamoruso/SecurityMonster/blob/main/screenshots/absences_vocal_command/AssenzeDaComandoVocale_screen2.png" style="width: 50%; height: 50%"/> </td>
<td><img src="https://github.com/vamoruso/SecurityMonster/blob/main/screenshots/absences_vocal_command/AssenzeDaComandoVocale_screen3.png" style="width: 50%; height: 50%"/> </td>
<td><img src="https://github.com/vamoruso/SecurityMonster/blob/main/screenshots/absences_vocal_command/AssenzeDaComandoVocale_screen4.png" style="width: 50%; height: 50%"/> </td>
<td><img src="https://github.com/vamoruso/SecurityMonster/blob/main/screenshots/absences_vocal_command/AssenzeDaComandoVocale_screen5.png" style="width: 50%; height: 50%"/> </td>  
</tr>  
     <tr>
      <td colspan=5>[Video](https://youtu.be/XBB3AnkUHHY)</td> 
   </tr> 
</table>   

###

## Credits

### Media

• Tutti gli screenshot del codice utilizzato in questo README sono stati realizzati da me su dispostivo Windows 11

### Ringraziamenti

* [Radare2](https://github.com/radareorg/radare2).
* [R2ai](https://github.com/radareorg/r2ai)


---
###

<h2 align="left">Vincenzo Amoruso <cite>2025</cite></h2>


![Markdown](https://img.shields.io/badge/markdown-%23000000.svg?style=flat=markdown&logoColor=white) ![GitHub contributors](https://img.shields.io/github/contributors/vamoruso/SecurityMonster?style=flat) ![GitHub last commit](https://img.shields.io/github/last-commit/vamoruso/SecurityMonster?style=flat)  ![GitHub Repo stars](https://img.shields.io/github/stars/vamoruso/SecurityMonster?style=social)  



