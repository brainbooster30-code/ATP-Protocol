# Deploy ATP Teacher ↔ School Server

Server e client comunicano via internet **senza toccare firewall né router**.
Il tunnel ngrok integrato crea automaticamente un indirizzo pubblico per il server.

---

## 1. SCUOLA — Avvio Server (con tunnel internet automatico)

```bash
# Installa pyngrok (basta una volta)
pip install pyngrok

# Registrati gratis su https://dashboard.ngrok.com/signup
# Copia il tuo auth token e salvalo:
#   Windows: setx NGROK_AUTH_TOKEN "tuo_token"
#   Linux:   echo 'export NGROK_AUTH_TOKEN=tuo_token' >> ~/.bashrc

# Avvia il server
cd ATP/sdk/examples
python school_server.py
```

Output:
```
═══════════════════════════════════
  🏫  ATP School Server — scuola-futura
  Listening on 127.0.0.1:8443
═══════════════════════════════════

  🌐 TUNNEL INTERNET ATTIVO
  Indirizzo pubblico: 2.tcp.ngrok.io:12345
  Client: python teacher_client.py 2.tcp.ngrok.io:12345
```

---

## 2. CASA — Connessione Insegnante (da qualsiasi parte del mondo)

```bash
cd ATP/sdk/examples
python teacher_client.py 2.tcp.ngrok.io:12345
```

Output:
```
  🏠  ATP Teacher Client — prof-rossi
  Connessione a: 2.tcp.ngrok.io:12345

✅ Connesso!
```

---

## 3. Senza ngrok (localhost, stessa macchina)

Se non installi pyngrok, il server mostra:

```
  📋 Client: python teacher_client.py 127.0.0.1:8443
```

Client:
```bash
python teacher_client.py                     # localhost
python teacher_client.py 192.168.1.50:8443   # rete locale
python teacher_client.py 2.tcp.ngrok.io:12345  # internet via tunnel
```

---

## 4. Menu Insegnante

```
═════════════════════════════════════════
  🏠  Prof. Rossi — Connesso a 2.tcp.ngrok.io:12345
  MCC scuola: ee84bca8fa43549f...
═════════════════════════════════════════
  1. 📋  Invia piano didattico
  2. 📊  Consulta voti studente
  3. 📝  Assegna compito
  4. 📚  Richiedi risorse didattiche
  5. 🚨  Segnala incidente
  6. 💬  Chat con AI scolastica (DeepSeek)
  0. 🚪  Esci
```

---

## 5. Database

I dati sono salvati in `school_db.json`. Persistono tra riavvii.

---

## 6. Requisiti

- Python 3.10+
- `pip install pyngrok` (per tunnel internet — opzionale)
- Account ngrok gratuito (per tunnel internet — opzionale)
- Nessun firewall da aprire, nessun port forwarding, nessuna VPN
