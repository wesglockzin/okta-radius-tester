from __future__ import annotations

import os
import sys

SIGN_IN_ISSUER = "https://host.example.com"
V01_KEYS = ("RT_TENANT", "RADIUS_SHARED_SECRET")


def cluster_app():
    base = os.environ.get("APP_BASE_URL", "").rstrip("/")
    if not base.startswith("https://"):
        sys.exit(f"[radius-tester] APP_BASE_URL must be this route's https:// URL, got {base!r} — refusing")
    missing = [k for k in ("OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "FLASK_SECRET_KEY")
               if not os.environ.get(k)]
    if missing:
        sys.exit(f"[radius-tester] deployment env missing {missing} — refusing to start without the sign-in")
    if os.environ["OIDC_ISSUER"].rstrip("/") != SIGN_IN_ISSUER:
        sys.exit(f"[radius-tester] sign-in issuer {os.environ['OIDC_ISSUER']} is not PROD Okta "
                 f"({SIGN_IN_ISSUER}) — the tool signs in with PROD; the tenants it tests are data. Refusing")
    leftover = [k for k in V01_KEYS if k in os.environ]
    if leftover:
        sys.exit(f"[radius-tester] deployment env still has v0.1 keys {leftover} — tenants and their "
                 f"shared secrets live in the registry Secret now; remove them from the -env secret. Refusing")
    if not os.environ.get("FLEET_STATE_SECRET"):
        sys.exit("[radius-tester] no FLEET_STATE_SECRET — set stateSecret in the values file "
                 "(the chart wires the Secret and the ServiceAccount allowed to use it). Refusing")

    import app
    import registry
    import state_store

    try:
        doc, _ = app.load_registry()
    except (state_store.StateError, registry.Invalid) as e:
        sys.exit(f"[radius-tester] tenant registry unusable: {e} — refusing")

    print(f"  Okta RADIUS Tester (OpenShift) v{app.APP_VERSION} · sign-in {SIGN_IN_ISSUER} · "
          f"registry secret/{app.STATE_SECRET}")
    for t in registry.public(doc):
        print(f"  {t['label']}: {t['app']} UDP {t['port']} · agents {', '.join(t['agents']) or '(none)'}")
    return app.app
