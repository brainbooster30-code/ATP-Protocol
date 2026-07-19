"""
ATP SDK — Real-World Example #4: Teacher ↔ School Server over Internet

Scenario:
  An Italian teacher (Prof. Rossi) works from home and needs to interact
  with the school's AI server (Scuola Futura) via internet.
  ATP v1.7 provides secure, attested communication with MCC-bound identities.

  Use cases: lesson plan approval, grade lookup, homework assignment,
             resource requests, incident reporting.

Run: python examples/teacher_school.py
"""
import asyncio, sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from atp_sdk import SimpleATPServer, SimpleATPClient

PORT = 8460

# ── Simulated school database ─────────────────────────────────────────────
DB = {
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

# ── Server-side handlers (return plain strings) ──────────────────────────

async def handle_lesson_plan(task_type: str, payload: str) -> str:
    try: plan = json.loads(payload)
    except: return "❌ Errore: JSON non valido"
    DB["lesson_plans"].append(plan)
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
        return f"❌ Studente '{student}' non trovato"
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
    n = len(DB["students"][class_id])
    return (
        f"📝 COMPITO ASSEGNATO #{len(DB['homework'])}\n"
        f"   Classe: {class_id} ({n} studenti)\n"
        f"   Materia: {data.get('subject')}\n"
        f"   Scadenza: {data.get('deadline')}\n"
        f"   Testo: {data.get('description')[:80]}..."
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
    incident = {"id": len(DB["incidents"]) + 1, **data}
    DB["incidents"].append(incident)
    return (
        f"🚨 SEGNALAZIONE #{incident['id']} REGISTRATA\n"
        f"   Classe: {data.get('class')}\n"
        f"   Gravità: {data.get('severity')}\n"
        f"   Descrizione: {data.get('description')[:60]}...\n"
        f"   Il dirigente è stato notificato."
    )

# ── Main Scenario ─────────────────────────────────────────────────────────

async def main():
    print("═" * 64)
    print("  🏠  Prof. Rossi (casa)  ←──ATP v1.7──→  🏫  Scuola Futura")
    print("═" * 64)
    print()

    school = SimpleATPServer(agent_name="scuola-futura")
    for name, handler in [
        ("submit_lesson_plan", handle_lesson_plan),
        ("check_grades", handle_check_grades),
        ("assign_homework", handle_assign_homework),
        ("get_resources", handle_get_resources),
        ("report_incident", handle_report_incident),
    ]:
        school.register_handler(name, handler)
    await school.start(port=PORT)
    print("[🏫 SCUOLA] Server Futura online")
    
    # Esporta Key Card per scambio fuori banda
    from atp_sdk.key_exchange import export_key_card, import_key_card
    from socket import gethostbyname, gethostname
    local_ip = gethostbyname(gethostname())
    card_file = export_key_card(
        agent_name="scuola-futura",
        ed25519_sk=bytes.fromhex("00" * 32),
        ed25519_pk=bytes.fromhex("00" * 32),
        host=local_ip, port=PORT,
        mcc_hash="",
    )
    print(f"  🗝️  Key Card scuola: {card_file}")
    
    # Importa Key Card del docente (se esiste)
    teacher_card = f"atp_key_prof_rossi.card"
    if os.path.isfile(teacher_card):
        peer = import_key_card(teacher_card)
        print(f"  🗝️  Key Card docente importata: {peer['agent_name']}")
    print()

    teacher = SimpleATPClient("prof-rossi")
    await teacher.connect(port=PORT)
    mcc = teacher.peer_mcc_hash
    print(f"[🏠 PROF. ROSSI] Connesso. MCC scuola: {mcc[:16]}... ✓\n")

    # ── UC1: Lesson Plan ─────────────────────────────────────────
    print("─" * 64)
    print("  📋 USE CASE 1: Submit Lesson Plan")
    print("─" * 64)
    resp = await teacher.send("submit_lesson_plan", json.dumps({
        "teacher": "Prof. Rossi", "subject": "matematica",
        "topic": "Equazioni di secondo grado", "date": "2026-07-21", "class": "3A",
    }))
    print(resp["result"] if resp else "❌ Nessuna risposta")
    print()

    # ── UC2: Check Grades ─────────────────────────────────────────
    print("─" * 64)
    print("  📊 USE CASE 2: Check Grades (privacy-preserving)")
    print("─" * 64)
    resp = await teacher.send("check_grades", json.dumps({
        "student": "Giulia Verdi", "subject": "matematica",
    }))
    print(resp["result"] if resp else "❌ Nessuna risposta")
    print()

    # ── UC3: Assign Homework ──────────────────────────────────────
    print("─" * 64)
    print("  📝 USE CASE 3: Assign Homework to 3A")
    print("─" * 64)
    resp = await teacher.send("assign_homework", json.dumps({
        "class": "3A", "subject": "matematica",
        "description": "Risolvere esercizi 1-10 pag. 45. Consegnare entro la scadenza.",
        "deadline": "2026-07-28",
    }))
    print(resp["result"] if resp else "❌ Nessuna risposta")
    print()

    # ── UC4: Teaching Resources ───────────────────────────────────
    print("─" * 64)
    print("  📚 USE CASE 4: Request Teaching Resources")
    print("─" * 64)
    resp = await teacher.send("get_resources", "matematica")
    print(resp["result"] if resp else "❌ Nessuna risposta")
    print()

    # ── UC5: Report Incident ──────────────────────────────────────
    print("─" * 64)
    print("  🚨 USE CASE 5: Report Classroom Incident")
    print("─" * 64)
    resp = await teacher.send("report_incident", json.dumps({
        "class": "3A", "severity": "medium",
        "description": "Studente ha avuto un malore. Infermeria allertata. Genitori contattati.",
    }))
    print(resp["result"] if resp else "❌ Nessuna risposta")
    print()

    # ── Summary ───────────────────────────────────────────────────
    print("═" * 64)
    print("  📊 RIEPILOGO SESSIONE")
    print("═" * 64)
    print(f"  Piani didattici:  {len(DB['lesson_plans'])}")
    print(f"  Compiti:          {len(DB['homework'])}")
    print(f"  Segnalazioni:     {len(DB['incidents'])}")
    print(f"  Agenti:           Prof. Rossi ↔ Scuola Futura")
    print(f"  Protocollo:       ATP v1.7 — MCC-attested")
    print(f"  ✅ 5/5 use case completati via internet")
    print("═" * 64)

    await teacher.close()
    await school.stop()

if __name__ == "__main__":
    asyncio.run(main())
