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
### - Nell'ambiente virtuale *(venv) D:\Users\vincw\SecurityMonster*  eseguire il comando per installare il pacchetto per l'uso del protocollo https
    pip install pyopenssl 
### - Nell'ambiente virtuale *(venv) D:\Users\vincw\SecurityMonster*  eseguire il comando per installare il modello spaCy
    python -m spacy download en_core_web_md
### - Per avviare il web server Flask eseguire il comando
````Shell
  python.exe D:\Users\vincw\SecurityMonster\IAWebAppFlaskServer.py
````

> [!NOTE]
> Il server sarà in ascolto sulla porta 8000 all'indirizzo https://localhost:8000 


## Schema progetto e tecnologie

###

![Schema](documentation/SchemaArchitteturaTe.png)

<div align="left">
  <img src="https://cdn.jsdelivr.net/gh/devicons/devicon/icons/html5/html5-original.svg" height="40" alt="html5 logo"  />
  <img width="12" />
  <img src="https://cdn.jsdelivr.net/gh/devicons/devicon/icons/css3/css3-original.svg" height="40" alt="jquery logo"  />
  <img width="12" />
  <img src="https://cdn.jsdelivr.net/gh/devicons/devicon/icons/bootstrap/bootstrap-original.svg" height="40" alt="bootstrap logo"  />
  <img width="12" />
  <img src="https://cdn.jsdelivr.net/gh/devicons/devicon/icons/javascript/javascript-original.svg" height="40" alt="javascript logo"  />
  <img width="12" />
  <img src="https://cdn.jsdelivr.net/gh/devicons/devicon/icons/jquery/jquery-original.svg" height="40" alt="jquery logo"  />
  <img width="12" />
  <img src="https://cdn.jsdelivr.net/gh/devicons/devicon/icons/handlebars/handlebars-original.svg" height="40" alt="handlebars logo"  />
  <img width="12" />
  <img src="https://cdn.jsdelivr.net/gh/devicons/devicon/icons/flask/flask-original.svg" height="40" alt="flask logo"  />
  <img width="12" />
  <img src="https://cdn.jsdelivr.net/gh/devicons/devicon/icons/python/python-original.svg" height="40" alt="python logo"  />
</div>


## Screenshots e video di test

### Applicazione IA con OCR per riconoscimento uno scontrino fiscale
    
<table>
<tr>
<td><img src="https://github.com/vamoruso/SecurityMonster/blob/main/screenshots/OCR/OCR_screen_1_1.png" style="width: 50%; height: 50%" /> </td>
<td><img src="https://github.com/vamoruso/SecurityMonster/blob/main/screenshots/OCR/OCR_screen_1.png" style="width: 50%; height: 50%" /> </td>
<td><img src="https://github.com/vamoruso/SecurityMonster/blob/main/screenshots/OCR/OCR_screen_2.png" style="width: 50%; height: 50%" /> </td>
<td><img src="https://github.com/vamoruso/SecurityMonster/blob/main/screenshots/OCR/OCR_screen_3.png" style="width: 50%; height: 50%" /> </td>
</tr>  
     <tr>
      <td colspan=4>[Video](https://youtu.be/9S8fvFy-tFI)</td> 
   </tr> 
</table>
    
### Applicazione pratica di IA con analisi del testo di un manuale pdf

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
    
### Applicazione IA di WebSpeech API ed analisi NLP con Spacy

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

• Tutti gli screenshot del codice utilizzato in questo README sono stati realizzati da me su dispostivo ***Android 13 modello OPPO A74 5G***

### Ringraziamenti

* [Hugging face Adamcodd OCR-free Document Understanding Transformer](https://huggingface.co/AdamCodd/donut-receipts-extract).
* [Hugging face BERT model for the Italian language](https://huggingface.co/osiria/bert-italian-cased-question-answering)
* [https://github.com/daveyjh](https://github.com/mdbootstrap/bootstrap-chat) - Per la UX del chatbot.


---
###

<h2 align="left">Vincenzo Amoruso <cite>2024</cite></h2>


![Markdown](https://img.shields.io/badge/markdown-%23000000.svg?style=flat=markdown&logoColor=white) ![GitHub contributors](https://img.shields.io/github/contributors/vamoruso/SecurityMonster?style=flat) ![GitHub last commit](https://img.shields.io/github/last-commit/vamoruso/SecurityMonster?style=flat)  ![GitHub Repo stars](https://img.shields.io/github/stars/vamoruso/SecurityMonster?style=social)  



