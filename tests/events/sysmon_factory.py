"""Re-export: the factory lives in the product code because IOC test events are synthesised at
run time (components/c4_validation/ioc_gates.py)."""
from components.c4_validation.sysmon_factory import (  # noqa: F401
    BROWSER,
    GUID,
    PROVIDER,
    PS,
    dns_query,
    event,
    network_connect,
    process_create,
)
