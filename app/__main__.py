"""Command line: ``python -m app serve | init-db | verify-audit``."""

from __future__ import annotations

import sys

from app.db.audit import verify_audit_chain
from app.db.session import init_db, session_scope
from app.wiring import build_context


def main(argv: list[str]) -> int:
    """Return the exit code."""
    cmd = argv[0] if argv else "help"
    if cmd == "serve":
        import uvicorn

        from app.api.main import create_app
        ctx = build_context()
        host = ctx.cfg.settings["api"]["host"]
        if host not in ("127.0.0.1", "localhost", "::1"):
            print("refusing to bind to a non-local address (blueprint section 19.6)")
            return 2
        uvicorn.run(create_app(ctx), host=host, port=int(ctx.cfg.settings["api"]["port"]))
        return 0
    if cmd == "init-db":
        ctx = build_context()
        init_db(ctx.engine)
        print("database ready")
        return 0
    if cmd == "verify-audit":
        ctx = build_context()
        with session_scope(ctx.engine) as s:
            rep = verify_audit_chain(s)
        print(f"audit chain {'intact' if rep.ok else 'BROKEN'}: {rep.checked} events checked"
              + ("" if rep.ok else f"; first bad event {rep.first_bad_id}: {rep.reason}"))
        return 0 if rep.ok else 1
    print(__doc__)
    return 0 if cmd == "help" else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
