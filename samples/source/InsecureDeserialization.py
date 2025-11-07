# InsecureDeserialization.py
import pickle

class User:
    def __init__(self, name):
        self.name = name

data = input("Inserisci dati serializzati: ")
user = pickle.loads(data)  # 🔴 Vulnerabile: input non verificato
print(f"Benvenuto {user.name}")
