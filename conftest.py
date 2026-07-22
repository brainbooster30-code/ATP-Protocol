"""
ATP v1.7 — pytest conftest: isolated fixtures, no singleton contamination.
"""
import sys, os, tempfile, time, pytest

# Ensure project root is on path
PROJECT_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


# ═══════════════════════════════════════════════════════════════════════════════
#  Fixtures: isolated state (no global singleton contamination)
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.fixture(autouse=True)
def _reset_global_state():
    """Reset all revocation singletons before each test.
    
    This is the key isolation mechanism: without it, tests leak state
    through get_cuckoo_filter(), get_root_store(), and get_gossip().
    """
    import revocation
    with revocation._revocation_lock:
        revocation._default_cuckoo = None
        revocation._default_root_store = None
        revocation._default_gossip = None
        revocation._default_degradation = None
    yield


@pytest.fixture
def isolated_cuckoo():
    """Return a fresh CuckooFilter with no stored state."""
    from revocation import CuckooFilter
    return CuckooFilter(buckets=256, slots=4)


@pytest.fixture
def isolated_root_store():
    """Return a RootStore backed by a temp file (isolated per test)."""
    from revocation import RootStore
    tmp = tempfile.mktemp(suffix=".json")
    rs = RootStore(path=tmp)
    yield rs
    try:
        os.unlink(tmp)
    except OSError:
        pass


@pytest.fixture
def default_authority():
    """Return the default shared authority (from authority.py)."""
    from authority import get_default_authority
    return get_default_authority()


@pytest.fixture
def agent_identity():
    """Return a fresh AgentIdentity with random keys."""
    from agent import AgentIdentity
    return AgentIdentity(agent_name="pytest-agent")


@pytest.fixture
def mcc_for_identity(agent_identity):
    """Return an MCC created from the agent identity fixture."""
    from agent import create_mcc_for_identity
    return create_mcc_for_identity(agent_identity)
