// Vulnerabilità: deserializzazione di oggetto non verificato
ObjectInputStream ois = new ObjectInputStream(new FileInputStream("data.ser"));
Object obj = ois.readObject(); // ⚠️ Può eseguire codice malevolo
