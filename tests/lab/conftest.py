"""Lab tests need the Wazuh manager container (blueprint §20.6). They are skipped unless
``ATIDEP_LAB=1`` is set, because every rule deployment restarts the manager (about 15 s)."""
import os

import pytest

from components.c4_validation.tier2 import LabError, LabManager
from tests.unit.test_c4_governance import world  # noqa: F401  (shared pipeline fixture)

LISTS = {"atidep-domains": "placeholder.invalid:\n", "atidep-ips": "240.0.0.1:\n"}


def pytest_collection_modifyitems(config, items):
    if os.environ.get("ATIDEP_LAB") == "1":
        return
    skip = pytest.mark.skip(reason="lab tests need the Wazuh container; set ATIDEP_LAB=1")
    for item in items:
        if "tests/lab" in str(item.fspath).replace("\\", "/"):
            item.add_marker(skip)


@pytest.fixture(scope="session")
def lab():
    os.environ.setdefault("WAZUH_API_USER", "wazuh-wui")
    os.environ.setdefault("WAZUH_API_PASSWORD", "MyS3cr37P450r.*-")   # the image's lab default
    try:
        manager = LabManager(os.environ.get("ATIDEP_LAB_CONTAINER", "wazuh"))
    except LabError as exc:
        pytest.skip(str(exc))
    if not manager.available():
        pytest.skip("the lab container is not running")
    manager.provision(LISTS)
    manager.reset_atidep_files(LISTS)          # start from a known state
    yield manager
    manager.reset_atidep_files(LISTS)          # and leave no test rule behind
