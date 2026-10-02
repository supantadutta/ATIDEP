"""Shared fixtures: a processed item with opportunities, approved rules, and a stub Wazuh API."""
from tests.unit.test_c4_governance import world  # noqa: F401  (re-exported fixture)
from tests.unit.test_c5_package_deploy import api, ioc_rule, sigma_rule  # noqa: F401
