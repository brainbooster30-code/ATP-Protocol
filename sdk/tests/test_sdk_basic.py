"""
ATP SDK v1.8 — pytest test suite.
Run: python -m pytest sdk/tests/ -v --tb=short
"""
import sys, os, tempfile, json, pytest

# Ensure both project root and SDK dir are on path
_PROJECT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))
_SDK_DIR = os.path.join(_PROJECT, "sdk")
for p in (_PROJECT, _SDK_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)


# ═══════════════════════════════════════════════════════════════════════════════
#  1. SDK IMPORTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestSDKImports:
    def test_imports(self):
        from atp_sdk import SimpleATPClient, SimpleATPServer, __version__
        assert callable(SimpleATPClient)
        assert callable(SimpleATPServer)
        assert __version__ == "1.8"


# ═══════════════════════════════════════════════════════════════════════════════
#  2. KEY CARD ROUNDTRIP
# ═══════════════════════════════════════════════════════════════════════════════

class TestKeyCard:
    def test_export_import(self):
        from atp_sdk.key_exchange import export_key_card, import_key_card
        from atp_core import generate_ed25519_keypair
        tmp = tempfile.mktemp(suffix=".card")
        sk, pk = generate_ed25519_keypair()
        path = export_key_card(
            agent_name="test-agent",
            ed25519_sk=sk, ed25519_pk=pk,
            host="127.0.0.1", port=9999,
            mcc_hash="abcd" * 8,
            output_path=tmp,
        )
        assert os.path.isfile(path)
        with open(path) as f:
            packet = json.load(f)
        assert "card" in packet and "signature" in packet
        assert packet["card"]["agent_name"] == "test-agent"
        imported = import_key_card(path)
        assert imported is not None
        assert imported["agent_name"] == "test-agent"
        assert imported["host"] == "127.0.0.1"
        assert imported["port"] == 9999
        assert imported["ed25519_pk"] == pk
        assert imported["mcc_hash"] == "abcd" * 8
        os.unlink(tmp)

    def test_tampered_signature(self):
        from atp_sdk.key_exchange import export_key_card, import_key_card
        from atp_core import generate_ed25519_keypair
        tmp = tempfile.mktemp(suffix=".card")
        sk, pk = generate_ed25519_keypair()
        export_key_card("test", ed25519_sk=sk, ed25519_pk=pk,
                        host="x", port=1, mcc_hash="00"*32, output_path=tmp)
        with open(tmp, "w") as f:
            json.dump({
                "card": {"agent_name": "test", "ed25519_pk": pk.hex(),
                         "host": "x", "port": 1, "mcc_hash": "00"*32},
                "signature": "00" * 64,
            }, f)
        with pytest.raises(ValueError, match="non valida"):
            import_key_card(tmp)
        os.unlink(tmp)


# ═══════════════════════════════════════════════════════════════════════════════
#  3. SimpleATPClient — construction
# ═══════════════════════════════════════════════════════════════════════════════

class TestClientConstruction:
    def test_construction(self):
        from atp_sdk import SimpleATPClient
        client = SimpleATPClient("test-sdk-client")
        assert client is not None
        assert client.agent_name == "test-sdk-client"
        assert not client.connected
        assert client._identity is None
        assert "disconnected" in repr(client)


# ═══════════════════════════════════════════════════════════════════════════════
#  4. SimpleATPServer — construction
# ═══════════════════════════════════════════════════════════════════════════════

class TestServerConstruction:
    def test_construction(self):
        from atp_sdk import SimpleATPServer
        server = SimpleATPServer("test-sdk-server")
        assert server is not None
        assert not server.running
        assert "stopped" in repr(server)
        assert server.identity is not None
        assert len(server.identity_sk) == 32 and len(server.identity_pk) == 32


# ═══════════════════════════════════════════════════════════════════════════════
#  5. KEY EXCHANGE — connect_with_key_card (no server = graceful None)
# ═══════════════════════════════════════════════════════════════════════════════

class TestKeyExchange:
    @pytest.mark.asyncio
    async def test_connect_no_server(self):
        from atp_sdk.key_exchange import export_key_card, connect_with_key_card
        from atp_core import generate_ed25519_keypair
        sk, pk = generate_ed25519_keypair()
        path = export_key_card("phantom-peer", ed25519_sk=sk, ed25519_pk=pk,
                                host="127.0.0.1", port=1, mcc_hash="")
        result = await connect_with_key_card(path, timeout=2.0)
        assert result is None
        os.unlink(path)


# ═══════════════════════════════════════════════════════════════════════════════
#  6. EXAMPLE FILES EXIST
# ═══════════════════════════════════════════════════════════════════════════════

class TestExamples:
    def test_example_files_exist(self):
        import importlib.util
        examples_dir = os.path.join(_SDK_DIR, "examples")
        if os.path.isdir(examples_dir):
            example_files = [f for f in os.listdir(examples_dir) if f.endswith(".py")]
            assert len(example_files) > 0
            for ef in sorted(example_files):
                modname = ef.replace(".py", "")
                spec = importlib.util.spec_from_file_location(
                    modname, os.path.join(examples_dir, ef)
                )
                assert spec is not None, f"{ef} does not load"
