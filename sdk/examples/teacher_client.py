"""
ATP SDK — Teacher Client (Prof. Rossi @ Home)
==============================================
Runs on the TEACHER'S home machine. Connects to the school server via internet.

Usage:  python teacher_client.py [school_ip]
        python teacher_client.py 192.168.1.100
        python teacher_client.py scuola-futura.example.com

Interactive menu-driven client for all school operations.
"""
import asyncio, sys, os, json, logging

# Ensure ATP parent project and SDK are importable
_EXAMPLES_DIR = os.path.dirname(os.path.abspath(__file__))
_SDK_DIR = os.path.normpath(os.path.join(_EXAMPLES_DIR, ".."))        # sdk/
_ATP_ROOT = os.path.normpath(os.path.join(_EXAMPLES_DIR, "..", ".."))  # ATP/
for _p in (_SDK_DIR, _ATP_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)
from atp_sdk import SimpleATPClient

logging.basicConfig(level=logging.WARNING)  # quiet mode, only errors
logger = logging.getLogger("teacher")

# ── Configuration ─────────────────────────────────────────────────────────────
DEFAULT_SCHOOL_HOST = "127.0.0.1"  # override with CLI argument
SCHOOL_PORT = 8443
TEACHER_NAME = "prof-rossi"


async def send_and_print(client: SimpleATPClient, task_type: str, payload: str, label: str):
    """Send a task and print the formatted response."""
    print(f"\n{'─' * 60}")
    print(f"  {label}")
    print(f"{'─' * 60}")
    try:
        resp = await client.send(task_type, payload)
        if resp and resp.get("result"):
            print(resp["result"])
        else:
            print("  ❌ Nessuna risposta dal server")
    except Exception as e:
        print(f"  ❌ Errore: {e}")


async def interactive_menu(client: SimpleATPClient):
    """Interactive menu for teacher operations."""
    while True:
        print(f"\n{'═' * 50}")
        print(f"  🏠  Prof. Rossi — Connesso a {client._host}:{client._port}")
        print(f"  MCC scuola: {client.peer_mcc_hash[:16] if client.peer_mcc_hash else '?'}...")
        print(f"{'═' * 50}")
        print("  1. 📋  Invia piano didattico")
        print("  2. 📊  Consulta voti studente")
        print("  3. 📝  Assegna compito")
        print("  4. 📚  Richiedi risorse didattiche")
        print("  5. 🚨  Segnala incidente")
        print("  6. 💬  Chat con AI scolastica (DeepSeek)")
        print("  0. 🚪  Esci")
        print(f"{'─' * 50}")

        try:
            choice = input("  Scelta: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  Arrivederci!")
            break

        if choice == "0":
            print("  Disconnessione...")
            break
        elif choice == "1":
            teacher = input("  Insegnante [Prof. Rossi]: ").strip() or "Prof. Rossi"
            subject = input("  Materia: ").strip()
            topic = input("  Argomento: ").strip()
            date = input("  Data (YYYY-MM-DD): ").strip()
            class_id = input("  Classe: ").strip()
            await send_and_print(client, "submit_lesson_plan", json.dumps({
                "teacher": teacher, "subject": subject, "topic": topic,
                "date": date, "class": class_id,
            }), "Invio piano didattico")
        elif choice == "2":
            student = input("  Nome studente: ").strip()
            subject = input("  Materia (invio per tutte): ").strip()
            await send_and_print(client, "check_grades", json.dumps({
                "student": student, "subject": subject,
            }), f"Consultazione voti: {student}")
        elif choice == "3":
            class_id = input("  Classe: ").strip()
            subject = input("  Materia: ").strip()
            desc = input("  Descrizione compito: ").strip()
            deadline = input("  Scadenza (YYYY-MM-DD): ").strip()
            await send_and_print(client, "assign_homework", json.dumps({
                "class": class_id, "subject": subject,
                "description": desc, "deadline": deadline,
            }), f"Assegnazione compito: {class_id}")
        elif choice == "4":
            subject = input("  Materia: ").strip()
            await send_and_print(client, "get_resources", subject, f"Risorse: {subject}")
        elif choice == "5":
            class_id = input("  Classe: ").strip()
            desc = input("  Descrizione incidente: ").strip()
            severity = input("  Gravità (low/medium/high) [medium]: ").strip() or "medium"
            await send_and_print(client, "report_incident", json.dumps({
                "class": class_id, "description": desc, "severity": severity,
            }), f"Segnalazione incidente: {class_id}")
        elif choice == "6":
            prompt = input("  Prompt: ").strip()
            if prompt:
                print(f"\n{'─' * 60}\n  💬 Chat AI\n{'─' * 60}")
                try:
                    response = await client.chat(prompt)
                    print(response)
                except Exception as e:
                    print(f"  ❌ Errore: {e}")
        else:
            print("  Scelta non valida")


async def main():
    # Determina host:port o .card file
    raw = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1:8443"
    
    # Se è un file .card, importa la Key Card
    if raw.endswith(".card") and os.path.isfile(raw):
        from atp_sdk.key_exchange import import_key_card
        peer = import_key_card(raw)
        host, port = peer["host"], peer["port"]
        print(f"  🗝️  Key Card importata: {peer['agent_name']}")
        print(f"     Indirizzo: {host}:{port}")
    elif ":" in raw:
        parts = raw.rsplit(":", 1)
        host, port = parts[0], int(parts[1])
    else:
        host, port = raw, SCHOOL_PORT

    print(f"  🏠  ATP Teacher Client — {TEACHER_NAME}")
    print(f"  Connessione a: {host}:{port}")
    print()

    client = SimpleATPClient(TEACHER_NAME)

    try:
        ok = await client.connect(host=host, port=port)
        if not ok:
            print(f"❌ Impossibile connettersi a {host}:{SCHOOL_PORT}")
            print("   Verifica che il server scolastico sia acceso.")
            return 1

        print(f"✅ Connesso!")
        print(f"   Scuola: {host}:{SCHOOL_PORT}")
        print(f"   MCC:    {client.peer_mcc_hash[:20]}...")

        await interactive_menu(client)

    except ConnectionRefusedError:
        print(f"❌ Connessione rifiutata da {host}:{SCHOOL_PORT}")
        print("   Il server potrebbe essere spento o la porta bloccata dal firewall.")
        return 1
    except OSError as e:
        print(f"❌ Errore di rete: {e}")
        return 1
    finally:
        await client.close()
        print("👋 Disconnesso.")

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
