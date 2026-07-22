"""
ATP v1.7 — pytest test suite.
Run:  python -m pytest test_all.py -v --tb=short

Each test function is isolated (see conftest.py _reset_global_state).
"""
import os
import time
import struct
import tempfile

import pytest
import cbor2

# ═══════════════════════════════════════════════════════════════════════════════
#  1. CRYPTO
# ═══════════════════════════════════════════════════════════════════════════════

class TestCrypto:
    def test_ed25519_keypair_lengths(self):
        from atp_core import generate_ed25519_keypair
        sk, pk = generate_ed25519_keypair()
        assert len(sk) == 32
        assert len(pk) == 32

    def test_ed25519_sign_and_verify(self):
        from atp_core import generate_ed25519_keypair, ed25519_sign, ed25519_verify
        sk, pk = generate_ed25519_keypair()
        sig = ed25519_sign(sk, b'test')
        assert len(sig) == 64
        assert ed25519_verify(pk, sig, b'test')
        assert not ed25519_verify(pk, sig, b'wrong')
        assert not ed25519_verify(b'x'*32, sig, b'test')

    def test_x25519_keypair(self):
        from atp_core import generate_x25519_keypair
        x_sk, x_pk = generate_x25519_keypair()
        assert len(x_sk) == 32
        assert len(x_pk) == 32

    def test_ed25519_x25519_separation(self):
        from atp_core import generate_ed25519_keypair, generate_x25519_keypair
        _, ed_pk = generate_ed25519_keypair()
        _, x_pk = generate_x25519_keypair()
        assert x_pk != ed_pk


# ═══════════════════════════════════════════════════════════════════════════════
#  2. BLAKE3
# ═══════════════════════════════════════════════════════════════════════════════

class TestBlake3:
    def test_hash_length(self):
        from atp_core import blake3_hash
        h = blake3_hash(b'hello')
        assert len(h) == 32

    def test_deterministic(self):
        from atp_core import blake3_hash
        assert blake3_hash(b'hello') == blake3_hash(b'hello')

    def test_different_input(self):
        from atp_core import blake3_hash
        assert blake3_hash(b'hello') != blake3_hash(b'world')


# ═══════════════════════════════════════════════════════════════════════════════
#  3. MCC LEAF
# ═══════════════════════════════════════════════════════════════════════════════

class TestMCCLeaf:
    def test_leaf_hash_32_bytes(self, isolated_cuckoo):
        from atp_core import MCCLeaf
        leaf = MCCLeaf(key='agent_pk', value=b'\x01'*32, salt=os.urandom(16))
        h = leaf.compute_leaf_hash()
        assert len(h) == 32

    def test_leaf_hash_formula(self, isolated_cuckoo):
        from atp_core import MCCLeaf, blake3_hash
        leaf = MCCLeaf(key='agent_pk', value=b'\x01'*32, salt=b'\x00'*16)
        h = leaf.compute_leaf_hash()
        k = b'agent_pk'
        manual = b'\x00' + b'\x00'*16 + struct.pack('!H', len(k)) + k + struct.pack('!I', 32) + b'\x01'*32
        assert h == blake3_hash(manual)

    def test_leaf_roundtrip(self, isolated_cuckoo):
        from atp_core import MCCLeaf
        leaf = MCCLeaf(key='agent_pk', value=b'\x01'*32, salt=b'\x00'*16)
        h = leaf.compute_leaf_hash()
        d = leaf.to_dict()
        leaf2 = MCCLeaf.from_dict(d)
        assert leaf2.compute_leaf_hash() == h


# ═══════════════════════════════════════════════════════════════════════════════
#  4. MERKLE TREE
# ═══════════════════════════════════════════════════════════════════════════════

class TestMerkleTree:
    def test_n0(self):
        from atp_core import _build_merkle_tree
        assert _build_merkle_tree([]) == b'\x00'*32

    def test_n1(self):
        from atp_core import MCCLeaf, _build_merkle_tree
        l0 = MCCLeaf(key='a', value=b'v', salt=b'\x00'*16)
        assert _build_merkle_tree([l0]) == l0.compute_leaf_hash()

    def test_sorted_determinism(self):
        from atp_core import MCCLeaf, _build_merkle_tree
        l0 = MCCLeaf(key='b', value=b'v1', salt=os.urandom(16))
        l1 = MCCLeaf(key='a', value=b'v2', salt=os.urandom(16))
        r1 = _build_merkle_tree([l0, l1])
        r2 = _build_merkle_tree([l1, l0])
        assert r1 == r2


# ═══════════════════════════════════════════════════════════════════════════════
#  5. MCC
# ═══════════════════════════════════════════════════════════════════════════════

class TestMCC:
    def test_basic_properties(self, default_authority, isolated_root_store):
        from atp_core import MCCLeaf
        auth = default_authority
        leaves = [
            MCCLeaf(key='agent_pk', value=b'\x01'*32, salt=os.urandom(16)),
            MCCLeaf(key='agent_sign_pk', value=b'\x02'*32, salt=os.urandom(16)),
        ]
        mcc = auth.sign_mcc(leaves=leaves)
        assert mcc.mcc_version == 1
        assert len(mcc.serial_number) == 16
        assert len(mcc.root_hash) == 32
        assert len(mcc.authority_sig) == 64

    def test_verify_valid(self, default_authority, isolated_root_store):
        from atp_core import MCCLeaf
        auth = default_authority
        pk = b'\x01'*32
        leaves = [
            MCCLeaf(key='agent_pk', value=pk, salt=os.urandom(16)),
            MCCLeaf(key='agent_sign_pk', value=b'\x02'*32, salt=os.urandom(16)),
        ]
        mcc = auth.sign_mcc(leaves=leaves)
        assert mcc.verify(auth.public_key)

    def test_verify_wrong_authority_fails(self, default_authority, isolated_root_store):
        from atp_core import MCCLeaf
        auth = default_authority
        leaves = [
            MCCLeaf(key='agent_pk', value=b'\x01'*32, salt=os.urandom(16)),
            MCCLeaf(key='agent_sign_pk', value=b'\x02'*32, salt=os.urandom(16)),
        ]
        mcc = auth.sign_mcc(leaves=leaves)
        assert not mcc.verify(b'x'*32)

    def test_key_separation_violation(self, default_authority, isolated_root_store):
        from atp_core import MCCLeaf
        auth = default_authority
        same_pk = b'\x01'*32
        leaves = [
            MCCLeaf(key='agent_pk', value=same_pk, salt=os.urandom(16)),
            MCCLeaf(key='agent_sign_pk', value=same_pk, salt=os.urandom(16)),
        ]
        mcc = auth.sign_mcc(leaves=leaves)
        assert not mcc.verify(auth.public_key)

    def test_expired(self, default_authority, isolated_root_store):
        from atp_core import MCCLeaf
        auth = default_authority
        leaves = [
            MCCLeaf(key='agent_pk', value=b'\x01'*32, salt=os.urandom(16)),
            MCCLeaf(key='agent_sign_pk', value=b'\x02'*32, salt=os.urandom(16)),
        ]
        mcc = auth.sign_mcc(leaves=leaves, expiry_date=100)
        assert not mcc.verify(auth.public_key)


# ═══════════════════════════════════════════════════════════════════════════════
#  6. MCC WIRE FORMAT (CBOR)
# ═══════════════════════════════════════════════════════════════════════════════

class TestMCCWire:
    def test_no_leaf_hash_in_cbor(self, default_authority, isolated_root_store):
        from atp_core import MCCLeaf
        auth = default_authority
        leaves = [
            MCCLeaf(key='agent_pk', value=b'\x01'*32, salt=os.urandom(16)),
            MCCLeaf(key='agent_sign_pk', value=b'\x02'*32, salt=os.urandom(16)),
        ]
        mcc = auth.sign_mcc(leaves=leaves)
        data = mcc.to_cbor()
        assert b'leaf_hash' not in data

    def test_cbor_has_8_fields(self, default_authority, isolated_root_store):
        from atp_core import MCCLeaf, MCC
        auth = default_authority
        leaves = [
            MCCLeaf(key='agent_pk', value=b'\x01'*32, salt=os.urandom(16)),
            MCCLeaf(key='agent_sign_pk', value=b'\x02'*32, salt=os.urandom(16)),
        ]
        mcc = auth.sign_mcc(leaves=leaves)
        decoded = cbor2.loads(mcc.to_cbor())
        expected = {'mcc_version','serial_number','root_hash','authority_id',
                    'authority_sig','expiry_date','leaves','critical_mask'}
        assert set(decoded.keys()) == expected

    def test_cbor_roundtrip(self, default_authority, isolated_root_store):
        from atp_core import MCCLeaf, MCC
        auth = default_authority
        leaves = [
            MCCLeaf(key='agent_pk', value=b'\x01'*32, salt=os.urandom(16)),
            MCCLeaf(key='agent_sign_pk', value=b'\x02'*32, salt=os.urandom(16)),
        ]
        mcc = auth.sign_mcc(leaves=leaves)
        mcc2 = MCC.from_cbor(mcc.to_cbor())
        assert mcc2.root_hash == mcc.root_hash
        assert mcc2.serial_number == mcc.serial_number


# ═══════════════════════════════════════════════════════════════════════════════
#  7. FRAME
# ═══════════════════════════════════════════════════════════════════════════════

class TestFrame:
    def test_header_structure(self):
        from atp_core import build_header
        h = build_header(0x01)
        assert set(h.keys()) == {'frame_type','frame_id','task_id','timestamp','atp_version'}
        assert isinstance(h['frame_type'], int)
        assert len(h['frame_id']) == 16

    def test_task_id_nil_for_control(self):
        from atp_core import build_header
        h = build_header(0x30)
        assert h['task_id'] == b'\x00'*16

    def test_frame_encode_decode(self):
        from atp_core import build_header, encode_frame
        req = {'header': build_header(0x01), 'task_type': 'echo',
               'task_payload': b'test', 'deadline_ms': 30000,
               'metadata': {'p': 4}, 'priority_hint': 4}
        enc = encode_frame(req)
        length = struct.unpack('!I', enc[:4])[0]
        assert length == len(enc)-4
        dec = cbor2.loads(enc[4:])
        assert dec['task_type'] == 'echo'

    def test_task_error_with_server_time(self):
        from atp_core import build_header, encode_frame
        err = {'header': build_header(0x04), 'error_code': 0x0C,
               'error_message': 'Clock skew', 'server_time_ms': 1700000000000}
        enc = encode_frame(err)
        dec = cbor2.loads(enc[4:])
        assert dec['server_time_ms'] == 1700000000000


# ═══════════════════════════════════════════════════════════════════════════════
#  8. FRAME TYPES COVERAGE
# ═══════════════════════════════════════════════════════════════════════════════

class TestFrameTypes:
    def test_count_24(self):
        from atp_core import FRAME_TYPES
        assert len(FRAME_TYPES) == 24

    def test_all_codes_present(self):
        from atp_core import FRAME_TYPES
        expected = {0x01,0x02,0x03,0x04,0x05,0x10,0x11,0x12,0x13,0x14,0x15,0x16,
                    0x20,0x21,0x30,0x31,0x40,0x41,0x42,0x50,
                    0x60,0x61,0x62,0x63}
        assert set(FRAME_TYPES.keys()) == expected


# ═══════════════════════════════════════════════════════════════════════════════
#  9. ERROR CODES
# ═══════════════════════════════════════════════════════════════════════════════

class TestErrorCodes:
    def test_count_15(self):
        from atp_core import ERROR_CODES
        assert len(ERROR_CODES) == 15

    def test_dispositions(self):
        from atp_core import ERROR_CODES
        dispositions = {
            0x01:'close',0x02:'close',0x03:'close',0x04:'close',0x05:'close',
            0x06:'close',0x07:'close',0x08:'close',0x09:'close_stream',
            0x0A:'close_stream',0x0B:'close_stream',0x0C:'close_stream',
            0x0D:'recoverable',0x0E:'close_stream',0x0F:'close_stream',
        }
        for code, disp in dispositions.items():
            assert ERROR_CODES[code][1] == disp, f"0x{code:02X} expected {disp}"


# ═══════════════════════════════════════════════════════════════════════════════
#  10. CUCKOO FILTER
# ═══════════════════════════════════════════════════════════════════════════════

class TestCuckooFilter:
    def test_empty(self, isolated_cuckoo):
        cf = isolated_cuckoo
        assert cf.size == 0
        assert cf.load_factor == 0.0

    def test_insert_and_contains(self, isolated_cuckoo):
        cf = isolated_cuckoo
        for i in range(100):
            cf.insert(f'key-{i}'.encode())
        assert cf.size == 100
        assert cf.contains(b'key-50')
        assert not cf.contains(b'nope')
        assert cf.load_factor < 1.0

    def test_remove(self, isolated_cuckoo):
        cf = isolated_cuckoo
        cf.insert(b'key-50')
        cf.remove(b'key-50')
        assert not cf.contains(b'key-50')


# ═══════════════════════════════════════════════════════════════════════════════
#  11. ROOT STORE
# ═══════════════════════════════════════════════════════════════════════════════

class TestRootStore:
    def test_add_get(self):
        from revocation import RootStore
        tmp = tempfile.mktemp(suffix='.json')
        rs = RootStore(path=tmp)
        rs.add_authority('ca-1', bytes(32), ttl_seconds=3600)
        assert rs.get_authority('ca-1') == bytes(32)
        assert rs.get_authority('unknown') is None
        try: os.unlink(tmp)
        except OSError: pass

    def test_chain_manifest(self):
        from revocation import RootStore
        import cbor2 as _cbor2
        from atp_core import generate_ed25519_keypair, ed25519_sign
        tmp = tempfile.mktemp(suffix='.json')
        rs = RootStore(path=tmp)
        chain_sk, chain_pk = generate_ed25519_keypair()
        rs.add_authority('chain-ca', chain_pk)
        manifest = {
            "manifest_version": 1, "manifest_id": b'\x01'*16,
            "prev_manifest_id": b'\x00'*16, "timestamp": int(time.time()),
            "authority_id": "chain-ca", "authority_pk": chain_pk,
            "quorum_threshold": 1,
            "authorities": [{"authority_id": "child-ca", "pk": bytes(32)}],
        }
        manifest_bytes = _cbor2.dumps(manifest, canonical=True)
        sig = ed25519_sign(chain_sk, manifest_bytes)
        manifest["signature"] = sig
        signed = _cbor2.dumps(manifest, canonical=True)
        assert rs.chain_add(signed)
        assert len(rs.manifest['chain']) == 1
        assert rs.get_authority('child-ca') is not None
        assert not rs.chain_add(b'invalid')
        try: os.unlink(tmp)
        except OSError: pass


# ═══════════════════════════════════════════════════════════════════════════════
#  12. DEGRADATION POLICY
# ═══════════════════════════════════════════════════════════════════════════════

class TestDegradationPolicy:
    def test_active_confirmed(self, isolated_root_store):
        from revocation import DegradationPolicy
        dp = DegradationPolicy(active=True)
        assert dp.evaluate('ca-1', isolated_root_store) == 'UNCERTAIN'

    def test_active_unknown(self, isolated_root_store):
        from revocation import DegradationPolicy
        dp = DegradationPolicy(active=False)
        assert dp.evaluate('ca-1', isolated_root_store) == 'CONFIRMED'


# ═══════════════════════════════════════════════════════════════════════════════
#  13. REVOCATION INTEGRATION
# ═══════════════════════════════════════════════════════════════════════════════

class TestRevocation:
    def test_revoke_check(self):
        from revocation import revoke_serial, check_revoked
        assert revoke_serial(b'revoke-me')
        assert check_revoked(b'revoke-me')
        assert not check_revoked(b'clean-serial')

# ═══════════════════════════════════════════════════════════════════════════════
#  14. AGENT IDENTITY
# ═══════════════════════════════════════════════════════════════════════════════

class TestAgentIdentity:
    def test_keys_generated(self):
        from agent import AgentIdentity
        id1 = AgentIdentity('agent-1')
        id2 = AgentIdentity('agent-2')
        assert id1.x25519_pk != id2.x25519_pk
        assert id1.ed25519_pk != id2.ed25519_pk
        assert id1.x25519_pk != id1.ed25519_pk
        assert len(id1.x25519_pk) == 32
        assert len(id1.ed25519_pk) == 32

    def test_mcc_from_identity(self):
        from agent import AgentIdentity, create_mcc_for_identity
        id1 = AgentIdentity('agent-1')
        mcc = create_mcc_for_identity(id1)
        ml = {l.key: l.value for l in mcc.leaves}
        assert ml['agent_pk'] == id1.x25519_pk
        assert ml['agent_sign_pk'] == id1.ed25519_pk
        assert len(mcc.critical_mask) >= 6


# ═══════════════════════════════════════════════════════════════════════════════
#  15. AUTHORITY STORE
# ═══════════════════════════════════════════════════════════════════════════════

class TestAuthorityStore:
    def test_authority_in_root_store(self):
        from authority import get_default_authority
        from revocation import get_root_store
        auth = get_default_authority()
        pk_rs = get_root_store().get_authority(auth.authority_id)
        assert pk_rs == auth.public_key


# ═══════════════════════════════════════════════════════════════════════════════
#  16. HANDSHAKE RATE LIMITER
# ═══════════════════════════════════════════════════════════════════════════════

class TestHandshakeRateLimiter:
    @pytest.mark.asyncio
    async def test_rate_limit(self):
        from config import HandshakeRateLimiter
        hrl = HandshakeRateLimiter(max_attempts=3, window_s=60)
        assert await hrl.allow('1.2.3.4')
        assert await hrl.allow('1.2.3.4')
        assert await hrl.allow('1.2.3.4')
        assert not await hrl.allow('1.2.3.4')
        hrl.reset('1.2.3.4')
        assert await hrl.allow('1.2.3.4')
        assert await hrl.allow('5.6.7.8')


# ═══════════════════════════════════════════════════════════════════════════════
#  17. MONITOR
# ═══════════════════════════════════════════════════════════════════════════════

class TestMonitor:
    def test_metrics_text(self):
        from monitor import Monitor
        m = Monitor()
        m.add_event('TASK_START', {'task_type': 'echo', 'conn_id': 't1'})
        m.add_event('TASK_COMPLETE', {'task_type': 'echo', 'conn_id': 't1', 'latency_ms': 42})
        txt = m.get_metrics_text()
        assert 'tasks_sent' in txt
        prom = m.get_metrics_prometheus()
        assert 'HELP' in prom
        assert 'TYPE' in prom


# ═══════════════════════════════════════════════════════════════════════════════
#  18. STRUCTURED RESULT FORMAT (unbound agent)
# ═══════════════════════════════════════════════════════════════════════════════

class TestStructuredResult:
    @pytest.mark.asyncio
    async def test_unbound_returns_dict(self):
        from agent import ATPAgent, AgentIdentity
        agent = ATPAgent(AgentIdentity('dummy'))
        result = await agent.send_task('echo', b'test')
        assert isinstance(result, dict)
        assert result.get('status') == 'disconnected'


# ═══════════════════════════════════════════════════════════════════════════════
#  19. TASK STREAMING
# ═══════════════════════════════════════════════════════════════════════════════

class TestTaskStreaming:
    def test_chunk_format(self):
        chunk_resp = {
            "header": {"frame_type": 0x02, "task_id": b'\x11'*16},
            "status": 0, "result_payload": b'chunk-1',
            "partial": True, "sequence": 1,
        }
        assert chunk_resp.get('partial') == True
        assert chunk_resp.get('sequence') == 1
        assert len(chunk_resp.get('result_payload', b'')) > 0

    def test_non_streaming(self):
        single = {
            "header": {"frame_type": 0x02, "task_id": b'\x22'*16},
            "status": 0, "result_payload": b'single-result',
        }
        assert single.get('partial', False) == False
