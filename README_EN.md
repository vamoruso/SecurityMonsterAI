# SecurityMonsterAI

SecurityMonsterAI is an AI‑assisted cybersecurity toolkit designed for malware analysis, research, and educational purposes.  
It integrates YARA, ClamAV, Radare2, and local LLMs (via Ollama) to automate static and dynamic analysis workflows.

---

## 🚀 Features

- Automated static and dynamic malware analysis  
- YARA rule scanning with custom rule support  
- ClamAV signature‑based detection  
- Radare2 + r2ai for reverse‑engineering workflows  
- Local LLM support (DeepSeek, Llama, Mistral, Qwen, Gemma…)  
- Modular CLI architecture  
- Educational resources for cybersecurity students and researchers  

---

## 🧩 Architecture Overview

SecurityMonsterAI combines traditional malware‑analysis tools with modern AI models to enhance detection, explanation, and workflow automation.

Main components:
- **SecurityMonster.py** – core engine  
- **YARA definitions** – custom rules for pattern matching  
- **ClamAV integration** – signature scanning  
- **Radare2 + r2ai** – reverse engineering and AI‑assisted insights  
- **Ollama models** – local LLM inference  

---

## 📦 Installation

### Requirements
- Python 3.10+
- Ollama installed locally
- Radare2 + r2ai
- ClamAV

### Clone the repository
```bash
git clone https://github.com/vamoruso/SecurityMonsterAI
cd SecurityMonsterAI
