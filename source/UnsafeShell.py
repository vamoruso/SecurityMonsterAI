# Vulnerabilità: input utente passato direttamente a shell
import os
user_input = input("Nome file da cancellare: ")
os.system("rm " + user_input)  # ⚠️ Se user_input = "; rm -rf /", è disastroso
