"""
ATP SDK — School Server (Scuola Futura)
========================================================
Runs on the SCHOOL machine. Listens on 127.0.0.1:8443 for teacher connections.
Handles: lesson plans, grade lookup, homework, resources, incident reports.

Start:  python school_server.py
Stop:   Ctrl+C (graceful shutdown)
"""
import asyncio, sys, os, json, signal, logging

# Ensure ATP parent project and SDK are importable
_EXAMPLES_DIR = os.path.dirname(os.path.abspath(__file__))
_SDK_DIR = os.path.normpath(os.path.join(_EXAMPLES_DIR, ".."))        # sdk/
_ATP_ROOT = os.path.normpath(os.path.join(_EXAMPLES_DIR, "..", ".."))  # ATP/
for _p in (_SDK_DIR, _ATP_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)
from atp_sdk import SimpleATPServer
from atp_sdk.tunnel import AutoTunnel

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("school")

# ── Configuration ─────────────────────────────────────────────────────────────
HOST = "127.0.0.1"  # localhost — cambia in "0.0.0.0" per rete locale
PORT = 8443        # ATP TLS port
SCHOOL_NAME = "scuola-futura"

# ── School Database ──────────────────────────────────────────────────────────
DB_FILE = os.path.join(os.path.dirname(__file__), "school_db.json")

def load_db():
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    # Default database
    return {
        "students": {
            "3A": ["Marco Bianchi", "Giulia Verdi", "Luca Ferrari", "Anna Russo"],
            "3B": ["Paolo Neri", "Sofia Gialli", "Matteo Rossi", "Elena Blu"],
        },
        "grades": {
            "Marco Bianchi": {"matematica": 8, "italiano": 7, "storia": 9},
            "Giulia Verdi":  {"matematica": 9, "italiano": 8, "storia": 7},
            "Luca Ferrari":  {"matematica": 6, "italiano": 7, "storia": 6},
            "Anna Russo":    {"matematica": 10, "italiano": 9, "storia": 8},
        },
        "resources": {
            "matematica": ["Algebra lineare - dispense", "Esercizi geometria", "Teorema di Pitagora - slides"],
            "storia":     ["La Seconda Guerra Mondiale - mappe", "Rivoluzione Francese - timeline"],
            "italiano":   ["Divina Commedia - analisi canti", "Manzoni - I Promessi Sposi - guida"],
        },
        "lesson_plans": [],
        "homework": [],
        "incidents": [],
    }

DB = load_db()

def save_db():
    with open(DB_FILE, "w", encoding="utf-8") as f:
        json.dump(DB, f, indent=2, ensure_ascii=False)

# ── Task Handlers ─────────────────────────────────────────────────────────────

async def handle_lesson_plan(task_type: str, payload: str) -> str:
    try: plan = json.loads(payload)
    except: return "❌ Errore: JSON non valido"
    plan["timestamp"] = __import__("time").strftime("%Y-%m-%d %H:%M:%S")
    DB["lesson_plans"].append(plan)
    save_db()
    logger.info("Lesson plan approved from %s: %s", plan.get("teacher"), plan.get("topic"))
    return (
        f"✅ PIANO APPROVATO #{len(DB['lesson_plans'])}\n"
        f"   Materia: {plan.get('subject')} — {plan.get('topic')}\n"
        f"   Insegnante: {plan.get('teacher')}\n"
        f"   Data: {plan.get('date')} | Classe: {plan.get('class')}\n"
        f"   💡 Suggerimento AI: includere esercizi su '{plan.get('topic')}'"
    )

async def handle_check_grades(task_type: str, payload: str) -> str:
    try: data = json.loads(payload)
    except: return "❌ JSON non valido"
    student = data.get("student", "")
    subject = data.get("subject", "")
    grades = DB["grades"].get(student, {})
    if not grades:
        return f"❌ Studente '{student}' non trovato nel database"
    if subject:
        v = grades.get(subject)
        return f"📊 {student} — {subject}: {v}/10" if v else f"❌ Materia '{subject}' non trovata"
    lines = [f"📊 {student}:"]
    for s, v in grades.items(): lines.append(f"   {s}: {v}/10")
    return "\n".join(lines)

async def handle_assign_homework(task_type: str, payload: str) -> str:
    try: data = json.loads(payload)
    except: return "❌ JSON non valido"
    class_id = data.get("class", "")
    if class_id not in DB["students"]:
        return f"❌ Classe '{class_id}' inesistente"
    DB["homework"].append(data)
    save_db()
    n = len(DB["students"][class_id])
    logger.info("Homework assigned to %s: %s", class_id, data.get("subject"))
    return (
        f"📝 COMPITO ASSEGNATO #{len(DB['homework'])}\n"
        f"   Classe: {class_id} ({n} studenti)\n"
        f"   Materia: {data.get('subject')}\n"
        f"   Scadenza: {data.get('deadline')}\n"
        f"   Testo: {data.get('description', '')[:120]}..."
    )

async def handle_get_resources(task_type: str, payload: str) -> str:
    subject = payload.strip()
    resources = DB["resources"].get(subject, [])
    if not resources:
        avail = ", ".join(DB["resources"].keys())
        return f"📚 Nessuna risorsa per '{subject}'. Disponibili: {avail}"
    lines = [f"📚 RISORSE — {subject} ({len(resources)} trovate):"]
    for i, r in enumerate(resources, 1): lines.append(f"   {i}. {r}")
    return "\n".join(lines)

async def handle_report_incident(task_type: str, payload: str) -> str:
    try: data = json.loads(payload)
    except: return "❌ JSON non valido"
    incident = {"id": len(DB["incidents"]) + 1, "timestamp": __import__("time").strftime("%Y-%m-%d %H:%M:%S"), **data}
    DB["incidents"].append(incident)
    save_db()
    logger.warning("Incident reported in %s: %s", data.get("class"), data.get("description", "")[:60])
    return (
        f"🚨 SEGNALAZIONE #{incident['id']} REGISTRATA\n"
        f"   Classe: {data.get('class')}\n"
        f"   Gravità: {data.get('severity')}\n"
        f"   Descrizione: {data.get('description', '')[:80]}...\n"
        f"   Il dirigente è stato notificato."
    )

# ── Main ──────────────────────────────────────────────────────────────────────

async def main():
    print("═" * 64)
    print(f"  🏫  ATP School Server — {SCHOOL_NAME}")
    print(f"  Listening on {HOST}:{PORT}")
    print("═" * 64)
    print(f"  Database:     {DB_FILE}")
    print(f"  Students:     {sum(len(v) for v in DB['students'].values())}")
    print(f"  Lesson plans: {len(DB['lesson_plans'])}")
    print(f"  Homework:     {len(DB['homework'])}")
    print(f"  Incidents:    {len(DB['incidents'])}")
    print("═" * 64)
    print()

    server = SimpleATPServer(agent_name=SCHOOL_NAME)
    server.register_handler("submit_lesson_plan", handle_lesson_plan)
    server.register_handler("check_grades", handle_check_grades)
    server.register_handler("assign_homework", handle_assign_homework)
    server.register_handler("get_resources", handle_get_resources)
    server.register_handler("report_incident", handle_report_incident)

    await server.start(host=HOST, port=PORT)
    logger.info("Server running. Press Ctrl+C to stop.")

    # Start internet tunnel (zero-config: UPnP → ngrok → locale)
    tunnel = AutoTunnel()
    pub_url = await tunnel.start(PORT)
    if pub_url != f"127.0.0.1:{PORT}":
        method = tunnel.method.upper()
        print(f"\n  🌐 TUNNEL INTERNET ATTIVO ({method})")
        print(f"  Indirizzo pubblico: {pub_url}")
        print(f"  Client: python teacher_client.py {pub_url}")
        print()

    # Keep running until interrupted
    stop_event = asyncio.Event()
    def _sig_handler():
        logger.info("Shutdown signal received")
        stop_event.set()
    try:
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGINT, _sig_handler)
        loop.add_signal_handler(signal.SIGTERM, _sig_handler)
    except NotImplementedError:
        # Windows — signal handlers not supported, use KeyboardInterrupt
        pass

    try:
        await stop_event.wait()
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received")

    await server.stop()
    save_db()
    logger.info("Server stopped. Database saved.")

if __name__ == "__main__":
    asyncio.run(main())
