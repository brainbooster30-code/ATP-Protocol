# Deploy ATP Teacher ↔ School Server

Server e client comunicano via internet **senza toccare firewall né router**.
Il tunnel **UPnP nativo** integrato (pure Python, zero dipendenze esterne)
apre la porta sul router automaticamente e restituisce l'IP pubblico.

---

## 1. SCUOLA — Avvio Server (con tunnel UPnP automatico)

```bash
# Installa SDK (tunnel UPnP nativo incluso — nessuna dipendenza extra)
cd ATP/sdk
pip install -e .

# Avvia il server
cd ../sdk/examples
python school_server.py
```

Output:
```
═══════════════════════════════════
  🏫  ATP School Server — scuola-futura
  Listening on 127.0.0.1:8443
═══════════════════════════════════

  🌐 TUNNEL UPnP ATTIVO
  Indirizzo pubblico: 84.123.45.67:8443
  Client: python teacher_client.py 84.123.45.67:8443

  🗝️  KEY CARD ESPORTATA: atp_key_scuola_futura.card
  Consegna questo file all'insegnante (USB, email, QR code...)
```

---

## 2. CASA — Connessione Insegnante (da qualsiasi parte del mondo)

```bash
cd ATP/sdk/examples
python teacher_client.py 84.123.45.67:8443
```

Oppure via Key Card (zero servizi esterni):
```bash
python teacher_client.py atp_key_scuola_futura.card
```

Output:
```
  🏠  ATP Teacher Client — prof-rossi
  Connessione a: 84.123.45.67:8443

✅ Connesso!
```

---

## 3. Senza UPnP (locale o ngrok fallback)

Se il router non supporta UPnP, il server mostra:
```
  📋 Client: python teacher_client.py 127.0.0.1:8443
```

Per tunnel internet alternativo (ngrok):
```bash
pip install pyngrok
setx NGROK_AUTH_TOKEN "tuo_token"
python school_server.py
```

Client:
```bash
python teacher_client.py                     # localhost
python teacher_client.py 192.168.1.50:8443   # rete locale
python teacher_client.py 2.tcp.ngrok.io:12345  # internet via ngrok
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
- Tunnel internet: **UPnP nativo** (zero dipendenze, standard library pure Python)
- `pyngrok` (opzionale) — solo se UPnP non disponibile
- Account ngrok gratuito (opzionale — solo per fallback ngrok)
- Nessun firewall da aprire, nessun port forwarding, nessuna VPN
