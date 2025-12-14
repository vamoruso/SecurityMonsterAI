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

# Estensioni di file compressi
ARCHIVE_EXTENSIONS = {
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.tgz', '.tbz2',
    '.zst', '.cab', '.iso', '.img', '.dmg', '.apk', '.jar', '.war', '.ear'
}

#Estensioni di documenti
DOCUMENT_EXTENSIONS = {
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt', '.ods', '.odp'
}

#Estensioni di file log e log eventi windows
LOG_EXTENSIONS = {
    '.log','.txt','.pcap','.evtx'
}



# Configurazione modelli
SOURCE_CODE_MODELS = [
    "qwen3-coder:30b",
    #"codellama:13b",
    "codellama:13b-instruct",
    "deepseek-coder:33b-instruct-q5_K_M",
]

SOURCE_CODE_PROMPT_TEMPLATE = """
Analizza il seguente codice sorgente e rispondi SOLO ed esclusivamente in formato JSON valido, senza commenti o testo aggiuntivo.

Identifica:
1. "malicious" — True se contiene codice malevolo (es. reverse shell, keylogger, download eseguibili), False altrimenti.
2. "vulnerabilities" — Lista di vulnerabilità trovate (es. "SQL injection", "buffer overflow", "hardcoded password"). Se nessuna, lista vuota.
3. "logical_errors" — Lista di errori logici o bug potenziali (es. "divisione per zero", "variabile non inizializzata", "ciclo infinito"). Se nessuno, lista vuota.
4. "explanation" — Breve spiegazione (max 200 caratteri).

Esempio di risposta JSON che devi produrre:
{{
  "malicious": false,
  "vulnerabilities": ["SQL injection in query"],
  "logical_errors": ["missing null check"],
  "explanation": "Il codice è sicuro ma presenta vulnerabilità SQL e manca controllo null."
 }}
Rispondi solo in JSON con le proprietà "malicious": false,  "vulnerabilities": ["SQL injection in query"],  "logical_errors": ["missing null check"], "explanation": "Il codice è sicuro ma presenta vulnerabilità SQL e manca controllo null."
CODICE:{code}
Rispondi solo in JSON con le proprietà "malicious": false,  "vulnerabilities": ["SQL injection in query"],  "logical_errors": ["missing null check"], "explanation": "Il codice è sicuro ma presenta vulnerabilità SQL e manca controllo null."
"""


# ✅ Modelli Ollama
LOG_AI_MODELS = [
    #"codellama:latest",
    #"llama2:latest",""
    "gemma3:12b",
    "llama3:8b",
    "mistral:latest"
]


# 🧠 Prompt per analisi log
LOG_PROMPT_TEMPLATE = """
Analizza i seguenti log/eventi e rispondi SOLO in formato JSON valido, senza testo aggiuntivo.

Identifica:
1. "anomalous" — True se rilevi traffico/eventi anomali (es. scansione porte, accessi ripetuti, errori critici), False altrimenti.
2. "patterns" — Lista di pattern anomali trovati (es. "SSH brute force", "Flood UDP", "Accesso amministratore fuori orario"). Se nessuno, lista vuota.
3. "risk_level" — Livello di rischio: "low", "medium", "high".
4. "explanation" — Breve spiegazione (max 200 caratteri).

Rispondi solo in JSON con le proprietà "anomalous":boolean,"patterns": array string,  "risk_level": string, "explanation": string
Esempio di risposta JSON:
```json
{{
  "anomalous": true,
  "patterns": ["SSH brute force from 192.168.1.100", "Multiple failed logins"],
  "risk_level": "high",
  "explanation": "Rilevati 50 tentativi di login SSH falliti in 2 minuti."
}}
LOG/EVENTI :{content}
"""

# ✅ Modelli Ollama
BIN_AI_MODELS = [
    #"codellama:latest",
    #"llama2:latest",""
    "gemma3:12b",
    "llama3:8b",
    "mistral:latest"
]


LIEF_SUPPORTED_EXTENSIONS = {
    ".exe": "PE (Windows Executable)",
    ".dll": "PE (Windows Dynamic Library)",
    ".sys": "PE (Windows Driver)",
    ".elf": "ELF (Linux Executable)",
    ".so": "ELF (Shared Object)",
    ".dylib": "Mach-O (macOS Dynamic Library)",
    ".dex": "DEX (Android)",
    ".oat": "OAT (Android)",
    ".art": "ART (Android)"
}

# ✅ Modelli Ollama
LIEF_AI_MODELS = [
    "gemma3:12b",
    "llama3:8b",
    "mistral:latest"
]

# 🧠 Prompt per analisi log
LIEF_PROMPT_TEMPLATE = """
"Analizza queste caratteristiche di file binari formattate in json e 
Valuta se può essere sospetto/malware sulla base di entropy, dll_count e import_count
{features}
Rispondi SOLO in formato JSON con questa struttura
Esempio di risposta JSON:
```json
{{
  "malware_likelihood": "<low|medium|high>",
  "reasoning": "<breve spiegazione>",
  "indicators": ["lista di indicatori rilevati"]
}}
"""

R2AI_MODEL_NAME= "gemma3:12b" # "qwen3-coder:30b"
R2AI_API="ollama"
R2AI_HOST_PORT="http://127.0.0.1:11434"
R2AI_MAX_RETRIES="2"
R2AI_PROMPTS = {
    "malware_indicators": "Identify malware signs in binary and summarize key risks. Focus on malware indicators and risks. Limit output to two entries classified as high risk. Reply in json with properties type, description and risk level (low/medium/high)!",
    "suspicious_api": "Detect suspicious API calls or system functions linked to malicious use. Limit output to two entries classified as high risk. Reply in json with properties type, description and risk level (low/medium/high)!", # Reply in json with properties 'Dangerous APIs' : [API1, API2, API3], 'Risk Category' : [memory/process/network/registry/crypto],'Severity': [low/medium/high/critical],Purpose: [brief description] ",
    "network_c2": "Highlight network functions suggesting C2 communication. Limit output to two entries classified as high risk. Reply in json with properties type, description and risk level (low/medium/high)!",# 'c2_likelihood': 'high|medium|low|none', 'indicators': ['connects to IP', 'uses HTTP', 'encrypts traffic'],'protocols': ['tcp', 'http', 'https'],'risk_score': 0-100 ",
    "obfuscation": "Spot obfuscation or packing patterns in code structure. Limit output to two entries classified as high risk. Reply in json with properties type, description and risk level (low/medium/high)!",
 }
