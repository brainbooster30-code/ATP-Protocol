#!/usr/bin/env python3
r"""ATP SDK — Production-Grade Example: EuroTech Solutions.

Scenario: multinazionale europea con 4 sedi che comunicano via ATP
v1.7 per condividere risorse agentiche (AI, knowledge base, task queue).

Sedi:
  [MIL] Centrale Milano     - AI cluster DeepSeek, orchestrazione, DB centrale
  [BER] Operations Berlino  - Monitoring, CI/CD, automazione infrastruttura
  [PAR] R&D Parigi          - Code analysis, document intelligence, knowledge base
  [MAD] Commerciale Madrid  - CRM, lead scoring, report vendite

Use case reali:
  1. AI load-balancing distribuito
  2. Knowledge base federata
  3. Code analysis da R&D per tutta l'azienda
  4. Report cross-sede
  5. Monitoring distribuito via health check
  6. Resilienza con riconnessione automatica
  7. Audit log con identita MCC

Esecuzione:
  # Demo locale (tutte le sedi sulla stessa macchina)
  python eurotech.py

  # Produzione (sede singola)
  python eurotech.py --sede centrale
  python eurotech.py --sede operations
  python eurotech.py --sede rd
  python eurotech.py --sede commerciale
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import sys
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# ── Path setup ──────────────────────────────────────────────────────────────────
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_SDK_DIR = Path(__file__).resolve().parent.parent
for p in (_SDK_DIR, _PROJECT_ROOT):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

# ── ATP SDK imports ─────────────────────────────────────────────────────────────
from atp_sdk import SimpleATPServer, SimpleATPClient

# ── Logging (strutturato in JSON per produzione) ────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("eurotech")

# JSON-structured audit log
_AUDIT_LOG: list[dict[str, Any]] = []


def audit(event: str, sede: str, **kwargs: Any) -> None:
    """Registra un evento di audit strutturato (traceable)."""
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "sede": sede,
        **kwargs,
    }
    _AUDIT_LOG.append(record)
    logger.info("AUDIT [%s] %s | %s", sede, event, json.dumps(kwargs))


# ═══════════════════════════════════════════════════════════════════════════════
#  1. CONFIGURAZIONE
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class SedeConfig:
    """Configurazione di una sede aziendale."""
    nome: str
    codice: str              # identificativo univoco
    host: str
    port: int
    ruolo: str               # "centrale" | "operations" | "rd" | "commerciale"
    ai_endpoint: bool        # se True, offre servizio AI Chat/DeepSeek
    kb_domini: list[str]     # domini di knowledge base gestiti (es. ["ml", "devops", ...])
    monitor_interval_s: int = 30  # health check ogni N secondi


# ── Configurazione delle 4 sedi ────────────────────────────────────────────────
SEDI_CONFIG: dict[str, SedeConfig] = {
    "centrale": SedeConfig(
        nome="Centrale Milano",
        codice="MIL",
        host="127.0.0.1",
        port=8440,
        ruolo="centrale",
        ai_endpoint=True,
        kb_domini=["generale", "ml", "ai", "strategia"],
    ),
    "operations": SedeConfig(
        nome="Operations Berlino",
        codice="BER",
        host="127.0.0.1",
        port=8441,
        ruolo="operations",
        ai_endpoint=False,
        kb_domini=["devops", "infra", "sicurezza", "ci-cd"],
    ),
    "rd": SedeConfig(
        nome="R&D Parigi",
        codice="PAR",
        host="127.0.0.1",
        port=8442,
        ruolo="rd",
        ai_endpoint=False,
        kb_domini=["code-review", "documenti", "ricerca", "brevetti"],
    ),
    "commerciale": SedeConfig(
        nome="Commerciale Madrid",
        codice="MAD",
        host="127.0.0.1",
        port=8443,
        ruolo="commerciale",
        ai_endpoint=True,
        kb_domini=["crm", "vendite", "report", "clienti"],
    ),
}


# ═══════════════════════════════════════════════════════════════════════════════
#  2. SHARED STATE (thread-safe)
# ═══════════════════════════════════════════════════════════════════════════════

class SharedState:
    """Stato condiviso e persistente di una sede (simula DB/backend)."""

    def __init__(self, sede: SedeConfig) -> None:
        self.sede = sede
        self._lock = asyncio.Lock()
        self._started_at: float = time.time()
        self._task_counter: int = 0
        self._kb: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._load: float = 0.0          # carico CPU-like 0.0 - 1.0
        self._peers: dict[str, Any] = {}  # sedi connesse
        self._audit_trail: list[dict] = []
        self._healthy: bool = True

        # Inizializza KB con dati di esempio per ogni dominio
        self._init_knowledge_base()

    def _init_knowledge_base(self) -> None:
        """Popola la knowledge base con dati fittizi ma realistici."""
        kb_data: dict[str, list[dict]] = {
            "centrale": {
                "ml": [
                    {"id": "ML-001", "title": "Best practices training modelli LLM",
                     "content": "Usare LoRA per fine-tuning, batch size 32, learning rate 2e-5"},
                    {"id": "ML-002", "title": "Deployment pipeline ML",
                     "content": "MLflow tracking → ONNX export → Triton inference server"},
                ],
                "ai": [
                    {"id": "AI-001", "title": "Policy utilizzo AI aziendale",
                     "content": "Vietato inserire dati sensibili nei prompt. Tutti i log sono auditati."},
                ],
                "strategia": [
                    {"id": "STR-001", "title": "Piano strategico 2026-2027",
                     "content": "Obiettivo: ridurre costi infrastruttura del 30% tramite ATP federation."},
                ],
            },
            "operations": {
                "devops": [
                    {"id": "OPS-001", "title": "CI/CD pipeline standard",
                     "content": "GitHub Actions → build → test → security scan → deploy su k8s staging"},
                    {"id": "OPS-002", "title": "Incident response procedure",
                     "content": "P1: 15min SLA. P2: 1h SLA. Runbook in confluence/ops/runbooks."},
                ],
                "infra": [
                    {"id": "INFRA-001", "title": "Architettura rete ATP",
                     "content": "Ogni sede ha server ATP su porta dedicata. Discovery via Key Card."},
                ],
                "sicurezza": [
                    {"id": "SEC-001", "title": "Policy rotazione chiavi",
                     "content": "Chiavi Ed25519 ruotate ogni 90 giorni. Revoca immediata in caso di compromissione."},
                ],
            },
            "rd": {
                "code-review": [
                    {"id": "CR-001", "title": "Standard code review ATP",
                     "content": "Type hints obbligatori. Docstring. Test coverage > 80%. Nessun todo in produzione."},
                ],
                "documenti": [
                    {"id": "DOC-001", "title": "Template documentazione tecnica",
                     "content": "RFC style: problem statement, design decisions, API spec, migration guide."},
                ],
                "brevetti": [
                    {"id": "PT-001", "title": "Brevetto ATP protocol",
                     "content": "MCC-based identity + distributed revocation. Deposito EUIPO #2026-ATP-001."},
                ],
            },
            "commerciale": {
                "crm": [
                    {"id": "CRM-001", "title": "Lead scoring model",
                     "content": "ML model: probability of conversion basato su engagement, industry, company size."},
                    {"id": "CRM-002", "title": "Sales playbook",
                     "content": "Discovery call → demo → technical validation → legal → commercial close."},
                ],
                "report": [
                    {"id": "RPT-001", "title": "Report trimestrale Q2 2026",
                     "content": "Revenue +15% YoY. Nuovi clienti: 24. Renewal rate: 92%."},
                ],
            },
        }

        corpo = kb_data.get(self.sede.codice.lower(), {})
        self._kb.update(corpo)

    async def increment_load(self, delta: float = 0.1) -> None:
        async with self._lock:
            self._load = min(1.0, self._load + delta)

    async def decrement_load(self, delta: float = 0.1) -> None:
        async with self._lock:
            self._load = max(0.0, self._load - delta)

    async def get_load(self) -> float:
        async with self._lock:
            return self._load

    async def get_uptime(self) -> float:
        return time.time() - self._started_at

    async def query_kb(self, dominio: str, query: str) -> list[dict]:
        """Cerca nella knowledge base locale."""
        async with self._lock:
            docs = self._kb.get(dominio, [])
            if not query.strip():
                return docs
            # Ricerca semplice per keywords nel titolo/content
            q = query.lower()
            return [
                d for d in docs
                if q in d["title"].lower() or q in d["content"].lower()
            ]

    async def add_kb_doc(self, dominio: str, title: str, content: str) -> dict:
        async with self._lock:
            doc = {"id": f"{dominio.upper()}-{len(self._kb[dominio])+1:03d}",
                   "title": title, "content": content}
            self._kb[dominio].append(doc)
            return doc

    async def register_peer(self, nome: str, client: Any) -> None:
        async with self._lock:
            self._peers[nome] = {"client": client, "connected_at": time.time()}

    async def get_peers(self) -> dict:
        async with self._lock:
            return dict(self._peers)

    async def health(self) -> dict:
        async with self._lock:
            return {
                "sede": self.sede.nome,
                "codice": self.sede.codice,
                "uptime_s": int(time.time() - self._started_at),
                "load": self._load,
                "task_count": self._task_counter,
                "healthy": self._healthy,
                "kb_domains": list(self._kb.keys()),
                "kb_total_docs": sum(len(v) for v in self._kb.values()),
                "connected_peers": len(self._peers),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }


# ═══════════════════════════════════════════════════════════════════════════════
#  3. TASK HANDLER (produzione)
# ═══════════════════════════════════════════════════════════════════════════════

class EuroTechHandlers:
    """Factory per i task handler di ogni sede.
    
    Ogni handler è un async callable(tipo_task: str, payload: str) → str.
    Firma compatibile con SimpleATPServer.on_task().
    """

    def __init__(self, sede: SedeConfig, state: SharedState) -> None:
        self.sede = sede
        self.state = state

    # ── Task handler: health check ───────────────────────────────────────

    async def handle_health(self, task_type: str, payload: str) -> str:
        """Pubblica lo stato di salute della sede (usato dal monitoring distribuito)."""
        health = await self.state.health()
        return json.dumps(health, indent=2)

    # ── Task handler: AI Chat ────────────────────────────────────────────

    async def handle_ai_chat(self, task_type: str, prompt: str) -> str:
        """Chiamata AI (DeepSeek) con load tracking."""
        await self.state.increment_load(0.15)
        try:
            from agent import ATPAgent
            audit("AI_CHAT", self.sede.codice, prompt_preview=prompt[:80])
            result = await ATPAgent.call_deepseek(prompt)
            if result is None:
                return json.dumps({"error": "DeepSeek API non disponibile",
                                   "sede": self.sede.codice})
            return json.dumps({"result": result, "sede": self.sede.codice,
                               "model": "deepseek-chat"})
        finally:
            await self.state.decrement_load(0.15)

    # ── Task handler: Knowledge Base query ───────────────────────────────

    async def handle_kb_query(self, task_type: str, payload: str) -> str:
        """Query alla knowledge base locale. Payload: JSON {dominio, query}."""
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            return json.dumps({"error": "Formato JSON non valido"})

        dominio = data.get("dominio", "")
        query = data.get("query", "")

        if dominio and dominio not in self.sede.kb_domini:
            return json.dumps({
                "error": f"Dominio '{dominio}' non gestito da {self.sede.nome}",
                "domini_disponibili": self.sede.kb_domini,
            })

        docs = await self.state.query_kb(dominio, query)
        audit("KB_QUERY", self.sede.codice, dominio=dominio, query_preview=query[:50],
              results=len(docs))

        return json.dumps({
            "sede": self.sede.codice,
            "dominio": dominio,
            "query": query,
            "results": docs,
            "count": len(docs),
        })

    # ── Task handler: AI-powered KB search (cross-sede) ──────────────────

    async def handle_ai_search(self, task_type: str, payload: str) -> str:
        """Cerca nella KB usando AI: il server usa DeepSeek per riassumere i risultati."""
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            return json.dumps({"error": "JSON non valido"})

        dominio = data.get("dominio", "")
        query = data.get("query", "")

        docs = await self.state.query_kb(dominio, query)
        if not docs:
            return json.dumps({"error": "Nessun documento trovato",
                               "sede": self.sede.codice})

        # Usa DeepSeek per riassumere i risultati
        from agent import ATPAgent
        context = "\n".join(f"- {d['title']}: {d['content'][:200]}" for d in docs)
        prompt = (
            f"Sei un assistente aziendale. L'utente cerca: '{query}' nel dominio '{dominio}'.\n"
            f"\nDocumenti trovati:\n{context}\n"
            f"\nFornisci una risposta sintetica e professionale in italiano, basata SOLO sui documenti sopra."
        )

        result = await ATPAgent.call_deepseek(prompt)
        audit("AI_SEARCH", self.sede.codice, dominio=dominio, query_preview=query[:50])

        return json.dumps({
            "sede": self.sede.codice,
            "risposta": result or "Nessuna risposta generata",
            "documenti_usati": len(docs),
        })

    # ── Task handler: Code Analysis (R&D) ────────────────────────────────

    async def handle_code_analysis(self, task_type: str, payload: str) -> str:
        """Analisi statica del codice. Solo R&D gestisce questo task.
        
        Payload: snippet di codice o URL di un file.
        """
        if self.sede.ruolo != "rd":
            return json.dumps({"error": "Solo R&D (Parigi) esegue code analysis",
                               "sede_competente": "rd"})

        await self.state.increment_load(0.2)
        try:
            from agent import ATPAgent
            snippet = payload[:2000]  # limita dimensione
            prompt = (
                f"Esegui code review del seguente codice. Analizza:\n"
                f"1. Problemi di sicurezza\n2. Performance\n3. Errori logici\n"
                f"4. Manutenibilità\n5. Code style\n\n```\n{snippet}\n```\n\n"
                f"Rispondi in italiano con un report strutturato."
            )
            result = await ATPAgent.call_deepseek(prompt)
            audit("CODE_ANALYSIS", self.sede.codice, snippet_len=len(snippet))

            return json.dumps({
                "sede": self.sede.codice,
                "report": result or "Analisi non disponibile",
                "snippet_preview": snippet[:100],
            })
        finally:
            await self.state.decrement_load(0.2)

    # ── Task handler: Request Report (tutte le sedi) ─────────────────────

    async def handle_report(self, task_type: str, payload: str) -> str:
        """Genera un report sullo stato della sede.

        Payload: tipo di report ("health", "kb", "load", "full")
        """
        report_type = payload.strip() or "health"

        if report_type == "health":
            data = await self.state.health()
        elif report_type == "kb":
            async with self.state._lock:
                data = {
                    "sede": self.sede.codice,
                    "domini": list(self.state._kb.keys()),
                    "totale_documenti": sum(len(v) for v in self.state._kb.values()),
                    "documenti": {k: v for k, v in self.state._kb.items()},
                }
        elif report_type == "load":
            data = {
                "sede": self.sede.codice,
                "load": await self.state.get_load(),
                "uptime_s": await self.state.get_uptime(),
            }
        else:
            # full report
            h = await self.state.health()
            async with self.state._lock:
                data = {**h, "kb": {k: v for k, v in self.state._kb.items()}}

        audit("REPORT", self.sede.codice, tipo=report_type)
        return json.dumps(data, indent=2, default=str)

    # ── Task handler: Cross-sede KB sync ─────────────────────────────────

    async def handle_kb_sync(self, task_type: str, payload: str) -> str:
        """Sincronizza un documento KB da un'altra sede."""
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            return json.dumps({"error": "JSON non valido"})

        dominio = data.get("dominio", "")
        title = data.get("title", "")
        content = data.get("content", "")

        if dominio not in self.sede.kb_domini:
            return json.dumps({"error": f"Dominio '{dominio}' non gestito",
                               "accettati": self.sede.kb_domini})

        doc = await self.state.add_kb_doc(dominio, title, content)
        audit("KB_SYNC", self.sede.codice, dominio=dominio, doc_id=doc["id"],
              from_sede=data.get("from", "unknown"))

        return json.dumps({"status": "ok", "doc": doc})

    # ── Task handler: Load balancing query ───────────────────────────────

    async def handle_get_load(self, task_type: str, payload: str) -> str:
        """Restituisce il carico attuale. Usato dall'orchestrator per routing."""
        load = await self.state.get_load()
        return json.dumps({
            "sede": self.sede.codice,
            "load": load,
            "ai_endpoint": self.sede.ai_endpoint,
        })


# ═══════════════════════════════════════════════════════════════════════════════
#  4. SEDE (agent logic)
# ═══════════════════════════════════════════════════════════════════════════════

class SedeAgent:
    """Agente ATP per una sede aziendale. Gestisce server + client verso le altre sedi."""

    def __init__(self, config: SedeConfig) -> None:
        self.config = config
        self.state = SharedState(config)
        self.handlers = EuroTechHandlers(config, self.state)
        self.server: Optional[SimpleATPServer] = None
        self._peers: dict[str, SimpleATPClient] = {}
        self._monitor_task: Optional[asyncio.Task] = None
        self._reconnect_task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()

    # ── Startup ──────────────────────────────────────────────────────────

    async def start(self, connect_peers: bool = True) -> None:
        """Avvia il server ATP e opzionalmente connette alle altre sedi."""
        codice = self.config.codice
        logger.info("═" * 64)
        logger.info("  🏢  %s [%s] — avvio sede ATP", self.config.nome, codice)
        logger.info("     Ruolo: %s | Porta: %s", self.config.ruolo, self.config.port)
        logger.info("     AI endpoint: %s | Domini KB: %s",
                    "✓" if self.config.ai_endpoint else "✗",
                    ", ".join(self.config.kb_domini))
        logger.info("═" * 64)

        # Avvia server ATP
        self.server = SimpleATPServer(agent_name=f"eurotech-{codice.lower()}")
        self._register_handlers()
        await self.server.start(port=self.config.port)

        audit("SERVER_START", codice, port=self.config.port)

        # Connette alle altre sedi (solo se richiesto)
        if connect_peers:
            await self._connect_to_peers()

        # Avvia monitoraggio periodico
        self._monitor_task = asyncio.create_task(self._monitor_loop())
        self._reconnect_task = asyncio.create_task(self._reconnect_loop())

        logger.info("✅ Sede %s [%s] pronta", self.config.nome, codice)

    async def connect_to_all_peers(self) -> None:
        """Connette a tutte le altre sedi (chiamato dopo che tutti i server sono up).
        
        Questo metodo va invocato DOPO che tutte le sedi hanno avviato il server,
        così da evitare race condition sulle connessioni peer-to-peer.
        """
        await self._connect_to_peers()

    def _register_handlers(self) -> None:
        """Registra tutti i task handler per questa sede."""
        assert self.server is not None
        h = self.handlers

        # Handler universali (tutte le sedi)
        self.server.register_handler("health", h.handle_health)
        self.server.register_handler("report", h.handle_report)
        self.server.register_handler("kb_query", h.handle_kb_query)
        self.server.register_handler("kb_sync", h.handle_kb_sync)
        self.server.register_handler("get_load", h.handle_get_load)
        self.server.register_handler("ai_search", h.handle_ai_search)

        # Handler specifici per ruolo
        if self.config.ai_endpoint:
            self.server.register_handler("ai_chat", h.handle_ai_chat)

        if self.config.ruolo == "rd":
            self.server.register_handler("code_analysis", h.handle_code_analysis)

        logger.info("  📋 Handler registrati per %s [%s]",
                    self.config.nome, self.config.codice)

    async def _connect_to_peers(self) -> None:
        """Connette alle altre sedi tramite ATP."""
        for codice, cfg in SEDI_CONFIG.items():
            if codice == self.config.codice:
                continue
            try:
                client = SimpleATPClient(
                    agent_name=f"eurotech-{self.config.codice.lower()}->{codice}"
                )
                ok = await client.connect(host=cfg.host, port=cfg.port)
                if ok:
                    self._peers[codice] = client
                    await self.state.register_peer(cfg.nome, client)
                    audit("PEER_CONNECT", self.config.codice,
                          peer=codice, host=cfg.host, port=cfg.port)
                    logger.info("  🔗 Connesso a %s [%s] — MCC: %s...",
                                cfg.nome, codice, (client.peer_mcc_hash or "?")[:16])
                else:
                    logger.warning("  ⚠️  Impossibile connettersi a %s [%s:%s]",
                                   cfg.nome, cfg.host, cfg.port)
            except Exception as exc:
                logger.warning("  ⚠️  Connessione a %s fallita: %s", codice, exc)

    # ── Monitoraggio periodico ───────────────────────────────────────────

    async def _monitor_loop(self) -> None:
        """Health check periodico verso tutte le sedi connesse."""
        while not self._stop_event.is_set():
            await asyncio.sleep(self.config.monitor_interval_s)

            for codice, client in list(self._peers.items()):
                try:
                    resp = await client.send("health", "ping")
                    if resp and resp.get("status") == 0:
                        cfg = SEDI_CONFIG.get(codice)
                        name = cfg.nome if cfg else codice
                        logger.debug("  ❤️  Health OK: %s [%s]", name, codice)
                    else:
                        logger.warning("  💔 Health FAIL: %s — response: %s",
                                       codice, resp)
                except Exception as exc:
                    logger.warning("  💔 Health check %s fallito: %s", codice, exc)

    async def _reconnect_loop(self) -> None:
        """Tenta di riconnettere sedi perse ogni 60 secondi."""
        while not self._stop_event.is_set():
            await asyncio.sleep(60)
            for codice, cfg in SEDI_CONFIG.items():
                if codice == self.config.codice:
                    continue
                if codice not in self._peers:
                    try:
                        client = SimpleATPClient(
                            agent_name=f"eurotech-{self.config.codice.lower()}->{codice}"
                        )
                        ok = await client.connect(host=cfg.host, port=cfg.port)
                        if ok:
                            self._peers[codice] = client
                            await self.state.register_peer(cfg.nome, client)
                            audit("PEER_RECONNECT", self.config.codice,
                                  peer=codice, host=cfg.host, port=cfg.port)
                            logger.info("  🔗 Riconnesso a %s [%s]", cfg.nome, codice)
                    except Exception:
                        pass

    # ── Cross-sede operations ─────────────────────────────────────────────

    async def broadcast_report(self, report_type: str = "health") -> dict[str, Any]:
        """Richiede report a tutte le sedi connesse e restituisce un aggregato."""
        results: dict[str, Any] = {}
        for codice, client in self._peers.items():
            try:
                cfg = SEDI_CONFIG.get(codice)
                name = cfg.nome if cfg else codice
                resp = await client.send("report", report_type)
                if resp and resp.get("status") == 0:
                    try:
                        payload = resp.get("result", "{}")
                        results[name] = json.loads(payload)
                    except json.JSONDecodeError:
                        results[name] = {"error": "risposta non valida", "raw": str(payload)}
                else:
                    results[name] = {"error": "nessuna risposta"}
            except Exception as exc:
                cfg = SEDI_CONFIG.get(codice)
                name = cfg.nome if cfg else codice
                results[name] = {"error": str(exc)}
        return results

    async def route_ai_chat(self, prompt: str) -> Optional[str]:
        """Instrada una chat AI alla sede con carico minore (load balancing)."""
        # Query load di tutte le sedi con AI endpoint
        best_sede: Optional[str] = None
        best_load: float = 2.0  # > 1.0 per iniziare

        for codice, client in self._peers.items():
            cfg = SEDI_CONFIG.get(codice)
            if not cfg or not cfg.ai_endpoint:
                continue
            try:
                resp = await client.send("get_load", "")
                if resp and resp.get("status") == 0:
                    try:
                        data = json.loads(resp.get("result", "{}"))
                        load = data.get("load", 1.0)
                        if load < best_load:
                            best_load = load
                            best_sede = codice
                    except (json.JSONDecodeError, KeyError):
                        pass
            except Exception:
                continue

        if best_sede is None:
            # Fallback: AI locale (se disponibile)
            if self.config.ai_endpoint:
                resultado = await self.handlers.handle_ai_chat("ai_chat", prompt)
                data = json.loads(resultado)
                return data.get("result")
            return "[ERRORE] Nessuna sede AI disponibile"

        logger.info("  🔀 Routing AI chat → %s (load: %.1f)",
                    SEDI_CONFIG[best_sede].nome, best_load)
        client = self._peers[best_sede]
        resp = await client.send("ai_chat", prompt)
        if resp and resp.get("status") == 0:
            try:
                data = json.loads(resp.get("result", "{}"))
                return data.get("result")
            except json.JSONDecodeError:
                return str(resp.get("result"))
        return None

    async def route_kb_query(self, dominio: str, query: str) -> list[dict]:
        """Query KB: cerca nella sede competente per dominio."""
        # Prima cerca nella KB locale
        local = await self.state.query_kb(dominio, query)
        if local:
            audit("KB_ROUTE", self.config.codice, dominio=dominio,
                  routed_to="locale", results=len(local))
            return local

        # Poi cerca tra i peer che gestiscono questo dominio
        for codice, client in self._peers.items():
            cfg = SEDI_CONFIG.get(codice)
            if cfg and dominio in cfg.kb_domini:
                try:
                    resp = await client.send("kb_query", json.dumps({
                        "dominio": dominio, "query": query,
                    }))
                    if resp and resp.get("status") == 0:
                        try:
                            data = json.loads(resp.get("result", "{}"))
                            audit("KB_ROUTE", self.config.codice, dominio=dominio,
                                  routed_to=codice, results=data.get("count", 0))
                            return data.get("results", [])
                        except json.JSONDecodeError:
                            pass
                except Exception:
                    continue

        return []

    # ── Shutdown ─────────────────────────────────────────────────────────

    async def stop(self) -> None:
        """Ferma la sede: disconnette peer e ferma il server."""
        self._stop_event.set()

        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass

        if self._reconnect_task:
            self._reconnect_task.cancel()
            try:
                await self._reconnect_task
            except asyncio.CancelledError:
                pass

        for codice, client in list(self._peers.items()):
            try:
                await client.close()
            except Exception:
                pass
            logger.info("  🔌 Disconnesso da %s", codice)

        if self.server:
            await self.server.stop()

        audit("SERVER_STOP", self.config.codice)
        logger.info("🛑 Sede %s [%s] fermata", self.config.nome, self.config.codice)


# ═══════════════════════════════════════════════════════════════════════════════
#  5. MAIN — Demo completa o esecuzione produzione
# ═══════════════════════════════════════════════════════════════════════════════

async def run_demo_completa() -> None:
    """Demo locale: avvia tutte le 4 sedi in parallelo e simula interazioni reali."""
    logger.info("")
    logger.info("╔══════════════════════════════════════════════════════════════╗")
    logger.info("║   🏢  EuroTech Solutions — ATP v1.7 Production Demo       ║")
    logger.info("║   Federazione multi-sede con 4 agenti autonomi            ║")
    logger.info("╚══════════════════════════════════════════════════════════════╝")
    logger.info("")

    # Avvia tutte le sedi (solo server, senza connessione peer)
    sedi = {codice: SedeAgent(cfg) for codice, cfg in SEDI_CONFIG.items()}
    for codice, agente in sedi.items():
        await agente.start(connect_peers=False)

    # Ora che tutti i server sono up, connetti i peer
    logger.info("  🔗 Connessione peer in corso (tutti i server sono up)...")
    for codice, agente in sedi.items():
        await agente.connect_to_all_peers()

    logger.info("")
    logger.info("═" * 64)
    logger.info("  ✅ TUTTE LE SEDI ONLINE — Esecuzione use case...")
    logger.info("═" * 64)
    logger.info("")

    # ── UC1: Health check distribuito ─────────────────────────────────
    logger.info("─" * 64)
    logger.info("  📋 UC1: HEALTH CHECK DISTRIBUITO")
    logger.info("     Ogni sede interroga tutte le altre via ATP.")
    logger.info("─" * 64)

    for codice, agente in sedi.items():
        reports = await agente.broadcast_report("health")
        logger.info("  [%s] Report ricevuti: %s", codice,
                     ", ".join(f"{k}: {v.get('load', '?')}" for k, v in reports.items()))
    logger.info("")

    # ── UC2: AI load balancing ────────────────────────────────────────
    logger.info("─" * 64)
    logger.info("  📋 UC2: AI LOAD BALANCING")
    logger.info("     Richiesta AI instradata alla sede col carico minore.")
    logger.info("─" * 64)

    # Simula carico sulla Centrale (Milano) per forzare routing ad altre sedi
    await sedi["centrale"].state.increment_load(0.8)

    for prompt in [
        "Spiega il concetto di federazione di agenti autonomi",
        "Quali sono i vantaggi della crittografia a curve ellittiche?",
    ]:
        result = await sedi["commerciale"].route_ai_chat(prompt)
        logger.info("  Prompt: %s", prompt[:60])
        logger.info("  Risultato: %s...", (result or "N/A")[:100])
        logger.info("")
    await sedi["centrale"].state.decrement_load(0.8)

    # ── UC3: Knowledge Base federata ──────────────────────────────────
    logger.info("─" * 64)
    logger.info("  📋 UC3: KNOWLEDGE BASE FEDERATA")
    logger.info("     Query KB instradata alla sede competente per dominio.")
    logger.info("─" * 64)

    test_queries = [
        ("ml", "best practices training"),
        ("devops", "pipeline"),
        ("crm", "lead scoring"),
        ("sicurezza", "rotazione chiavi"),
    ]
    for dominio, query in test_queries:
        logger.info("  Ricerca in [%s]: \"%s\"", dominio, query)
        results = await sedi["centrale"].route_kb_query(dominio, query)
        logger.info("    Trovati %d documenti", len(results))
        for r in results[:2]:
            logger.info("    • %s", r["title"])
    logger.info("")

    # ── UC4: Code Analysis (R&D) ──────────────────────────────────────
    logger.info("─" * 64)
    logger.info("  📋 UC4: CODE ANALYSIS (R&D Parigi)")
    logger.info("     La Commerciale richiede code review a R&D via ATP.")
    logger.info("─" * 64)

    codice_da_revisionare = """
def process_data(items):
    r = []
    for i in items:
        r.append(i * 2)
    return r
"""
    resp = await sedi["commerciale"]._peers["rd"].send(
        "code_analysis", codice_da_revisionare
    )
    if resp and resp.get("status") == 0:
        try:
            data = json.loads(resp.get("result", "{}"))
            report = data.get("report", "N/A")
            logger.info("  Code review response: %s...", report[:120])
        except json.JSONDecodeError:
            logger.info("  Code review response: %s", str(resp.get("result", ""))[:120])
    logger.info("")

    # ── UC5: Report cross-sede ────────────────────────────────────────
    logger.info("─" * 64)
    logger.info("  📋 UC5: REPORT CROSS-SEDE")
    logger.info("     Commerciale richiede report aggregato a tutte le sedi.")
    logger.info("─" * 64)

    reports = await sedi["commerciale"].broadcast_report("load")
    for sede, data in reports.items():
        load = data.get("load", "?")
        logger.info("  [%s] Carico: %s", sede, load)

    # Report completo dalla Centrale
    full = await sedi["centrale"].broadcast_report("full")
    for sede, data in full.items():
        kb_total = data.get("kb_total_docs", data.get("totale_documenti", "?"))
        uptime = data.get("uptime_s", 0)
        logger.info("  [%s] Uptime: %ds | KB docs: %s | Load: %s",
                     sede, uptime, kb_total, data.get("load", "?"))
    logger.info("")

    # ── UC6: AI Search sulla KB ───────────────────────────────────────
    logger.info("─" * 64)
    logger.info("  📋 UC6: AI-POWERED KB SEARCH")
    logger.info("     Cerca con AI nella knowledge base della sede competente.")
    logger.info("─" * 64)

    resp = await sedi["centrale"]._peers["operations"].send(
        "ai_search", json.dumps({"dominio": "devops", "query": "incident response"})
    )
    if resp and resp.get("status") == 0:
        try:
            data = json.loads(resp.get("result", "{}"))
            logger.info("  Risposta AI: %s...", data.get("risposta", "")[:150])
        except json.JSONDecodeError:
            pass
    logger.info("")

    # ── UC7: KB Sync cross-sede ───────────────────────────────────────
    logger.info("─" * 64)
    logger.info("  📋 UC7: KNOWLEDGE BASE SYNC")
    logger.info("     Centrale aggiunge un documento alla KB di Operations.")
    logger.info("─" * 64)

    resp = await sedi["centrale"]._peers["operations"].send(
        "kb_sync", json.dumps({
            "dominio": "devops",
            "title": "ATP deployment runbook v2",
            "content": "1. Avviare server ATP su porta designata. "
                       "2. Esportare Key Card per la sede remota. "
                       "3. Verificare connettività via health check. "
                       "4. Monitorare carico e latenza.",
            "from": "centrale",
        })
    )
    if resp and resp.get("status") == 0:
        try:
            data = json.loads(resp.get("result", "{}"))
            if data.get("status") == "ok":
                doc = data.get("doc", {})
                logger.info("  ✅ Documento sincronizzato: %s — %s", doc.get("id"), doc.get("title"))
        except json.JSONDecodeError:
            pass
    logger.info("")

    # ── Summary ───────────────────────────────────────────────────────
    logger.info("╔" + "═" * 60 + "╗")
    logger.info("║  📊 RIEPILOGO SESSIONE ATP — EuroTech Solutions           ║")
    logger.info("╠" + "═" * 60 + "╣")
    for codice, agente in sedi.items():
        cfg = SEDI_CONFIG[codice]
        peers = len(agente._peers)
        load = await agente.state.get_load()
        uptime = await agente.state.get_uptime()
        logger.info("║  🏢 %-20s [%s] peer=%d load=%.1f uptime=%ds  ║",
                     cfg.nome, codice, peers, load, int(uptime))
    logger.info("╠" + "═" * 60 + "╣")
    logger.info("║  Eventi audit: %-3d | Protocollo: ATP v1.7               ║",
                 len(_AUDIT_LOG))
    logger.info("║  Ogni transazione è firmata con MCC Ed25519              ║")
    logger.info("║  Nessun server centrale — federazione peer-to-peer       ║")
    logger.info("╚" + "═" * 60 + "╝")

    logger.info("")
    logger.info("Demo completata. Spegnimento sedi in corso...")

    # Ferma tutte le sedi
    for codice, agente in sedi.items():
        await agente.stop()


async def run_produzione(sede_codice: str) -> None:
    """Esecuzione produzione: avvia una sede singola e resta in ascolto."""
    cfg = SEDI_CONFIG.get(sede_codice)
    if not cfg:
        logger.error("Sede sconosciuta: %s. Opzioni: %s",
                      sede_codice, ", ".join(SEDI_CONFIG.keys()))
        sys.exit(1)

    agente = SedeAgent(cfg)
    await agente.start()

    # Gestione graceful shutdown
    stop_event = asyncio.Event()

    def _signal_handler() -> None:
        logger.info("⏹️  Segnale ricevuto. Spegnimento in corso...")
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, _signal_handler)
        except NotImplementedError:
            # Windows
            pass

    if sys.platform == "win32":
        # Su Windows, signal handler via polling
        while not stop_event.is_set():
            await asyncio.sleep(1)
    else:
        await stop_event.wait()

    await agente.stop()
    logger.info("✅ Sede %s fermata correttamente.", cfg.nome)


def main() -> None:
    """Entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="EuroTech Solutions — ATP v1.7 Multi-Site Agent Federation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Esempi:
  # Demo locale (4 sedi sulla stessa macchina)
  python eurotech.py

  # Produzione: avvia una sede specifica
  python eurotech.py --sede centrale
  python eurotech.py --sede operations
  python eurotech.py --sede rd
  python eurotech.py --sede commerciale
        """,
    )
    parser.add_argument("--sede", type=str, default="",
                        help="Codice sede da avviare (centrale, operations, rd, commerciale)")
    parser.add_argument("--config", type=str, default="",
                        help="Percorso file JSON di configurazione (opzionale)")

    args = parser.parse_args()

    if args.config:
        # Carica configurazione da file (produzione)
        with open(args.config) as f:
            external_config = json.load(f)
        for codice, cfg_data in external_config.get("sedi", {}).items():
            if codice in SEDI_CONFIG:
                for k, v in cfg_data.items():
                    if hasattr(SEDI_CONFIG[codice], k):
                        setattr(SEDI_CONFIG[codice], k, v)
                logger.info("Config esterna caricata per %s", codice)

    if args.sede:
        # Produzione: avvia una sede specifica
        asyncio.run(run_produzione(args.sede))
    else:
        # Demo locale
        asyncio.run(run_demo_completa())


if __name__ == "__main__":
    main()
