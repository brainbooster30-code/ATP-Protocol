# ATP v1.8 - Sistema delle autorita

## Ruolo delle autorita

Ogni agente ATP presenta una MCC (Merkle-Claim Card) firmata da una
authority Ed25519. Il peer accetta la MCC solo se puo verificare la firma
con una authority gia fidata nel RootStore, oppure se il bootstrap TOFU e
stato abilitato esplicitamente.

L'authority locale di default ha un `authority_id` stabile derivato dalla
public key (`atp-local-<hash>`), evitando collisioni tra macchine diverse.

Il RootStore runtime non vive nel repository: per default viene salvato in
`~/.atp/root_store.json` oppure `~/.atp/root_store.db` quando
`ROOT_STORE_BACKEND=sqlite`. `ATP_ROOT_STORE_PATH` puo sovrascrivere il
percorso.

## Verifica MCC

La verifica MCC e sempre attiva:

1. `mcc_version == 1`
2. `expiry_date > now`
3. tutte le chiavi in `critical_mask` sono presenti nelle foglie
4. `root_hash` viene ricalcolato dalle foglie ricevute
5. `authority_pk` viene recuperata dal RootStore
6. `authority_sig` viene verificata sul commitment CBOR
7. le chiavi agente sono separate (`agent_pk != agent_sign_pk`)
8. il seriale MCC non e revocato

Il commitment firmato include anche `critical_mask`, normalizzata come lista
ordinata e senza duplicati. Modificare le claim critiche invalida quindi la
firma dell'authority.

## Bootstrap della fiducia

### Strict (default)

`TRUST_BOOTSTRAP_MODE="strict"` rifiuta authority sconosciute. E la modalita
di default per SDK, client, server e QUIC.

Uso consigliato:

- produzione
- organizzazioni con RootStore pre-provisionato
- federazioni tra domini gia accreditati

### TOFU esplicito

`trust_bootstrap_mode="tofu"` abilita trust-on-first-use solo per quella
istanza di client/server/agente. In questo modo il bind frame include
`authority_pk`; il peer verifica la MCC con quella chiave e poi pinna
l'authority nel RootStore locale.

Uso consigliato:

- demo controllate
- primi test tra due macchine
- bootstrap iniziale seguito da revisione/pinning del RootStore

TOFU non salta la verifica della firma MCC: cambia solo la sorgente iniziale
della `authority_pk`.

## ROOT_STORE_UPDATE

`ROOT_STORE_UPDATE` supporta due manifest distinti:

### `rootstore-advertisement`

Manifest firmato dalla chiave Ed25519 dell'agente gia autenticato durante
l'handshake. Serve a confrontare stato e audit:

- verifica firma agente
- verifica `manifest_nonce` da 16 byte
- verifica `manifest_ts` entro 5 minuti
- conta authority note, ignote o in conflitto

Non aggiunge authority sconosciute.

### `authority-chain`

Manifest firmato da una authority gia presente nel RootStore locale. Solo
questa forma puo aggiungere nuove authority tramite `chain_add`.

La chain e stretta: se il signer non e gia fidato, il manifest viene
rifiutato. Questo evita che un agente autenticato possa elevare se stesso o
terzi a nuova authority.
`chain_add` aggiorna nonce, version tracking, authority e chain history solo
dopo schema valido, freshness valida, signer gia fidato e firma Ed25519 valida.
Un manifest con firma non valida non modifica lo stato locale.

## Modelli operativi

| Scenario | Configurazione consigliata |
|---|---|
| stesso processo / sviluppo locale | default `strict`; authority persistente in `~/.atp/` |
| due macchine in demo | `trust_bootstrap_mode="tofu"` su entrambi i lati |
| produzione single-org | RootStore pre-provisionato, `strict` |
| produzione multi-org | exchange fuori banda o `authority-chain` firmata da signer gia fidato |
| internet pubblico | integrare una PKI esterna o Web of Trust sopra il RootStore ATP |

## Federazione

La federation usa le chiavi Ed25519 dell'agente, non le chiavi authority:

- `PEER_DISCOVERY` deve essere firmato
- `TASK_FORWARD` deve essere firmato
- frame unsigned o con firma non valida vengono ignorati

La fiducia federation non modifica il RootStore: discovery e forwarding
autenticano il peer connesso, ma non concedono nuove authority.
