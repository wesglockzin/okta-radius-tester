import re, shutil, subprocess, sys, tempfile
from pathlib import Path
SRC = Path(__file__).resolve().parent
PY = sys.argv[1] if len(sys.argv) > 1 else sys.executable
M = [
 ("csrf gate", "app.py", 'if not want or not hmac.compare_digest(request.form.get("csrf", ""), want):', "if False:", "test_cluster.py", ["starts_gated", "accept_end_to_end", "tenants_and_agents"]),
 ("sign-in gate", "app.py", 'if OIDC_ENABLED and not session.get("user"):', "if False:", "test_cluster.py", ["starts_gated"]),
 ("PROD issuer", "_bootstrap.py", 'if os.environ["OIDC_ISSUER"].rstrip("/") != SIGN_IN_ISSUER:', "if False:", "test_cluster.py", ["is not PROD Okta"]),
 ("v0.1 leftovers", "_bootstrap.py", "    if leftover:", "    if False:", "test_cluster.py", ["RT_TENANT", "RADIUS_SHARED_SECRET"]),
 ("boot FLEET_STATE_SECRET", "_bootstrap.py", 'if not os.environ.get("FLEET_STATE_SECRET"):', "if False:", "test_cluster.py", ["set stateSecret in the values file (the chart"]),
 ("import FLEET_STATE_SECRET", "app.py", "    if not STATE_SECRET:", "    if False:", "test_cluster.py", ["app_import_refuses_in_cluster"]),
 ("boot reads registry", "_bootstrap.py", "doc, _ = app.load_registry()", "doc = registry.empty()", "test_cluster.py", ["HTTP 404", "HTTP 403", "is not valid JSON", "tenants.qa"]),
 ("registry check on load", "app.py", "return reg.check(doc), version", "return doc or reg.empty(), version", "test_cluster.py", ["tenants.qa"]),
 ("send lookup", "app.py", "tenant = reg.lookup(doc, key, agent)", 'tenant = next(iter(doc["tenants"].values()))', "test_cluster.py", ["accept_end_to_end"]),
 ("respond lookup", "app.py", 'tenant = reg.lookup(doc, flow["tenant"], flow["agent"])', 'tenant = doc["tenants"][flow["tenant"]]', "test_cluster.py", ["removed_mid_challenge"]),
 ("Conflict -> 409", "app.py", "    except state_store.Conflict:\n", "    except KeyError:\n", "test_cluster.py", ["tenants_and_agents"]),
 ("PUT carries resourceVersion", "state_store.py", "body = copy.deepcopy(version)", 'body = copy.deepcopy(version); body["metadata"].pop("resourceVersion", None)', "test_state_store.py", ["concurrent_write"]),
 ("token re-read", "state_store.py", 'token = _read(f"{SA_DIR}/token")', 'token = getattr(self, "_t", None) or _read(f"{SA_DIR}/token"); self._t = token', "test_state_store.py", ["token_is_reread"]),
 ("public() has no secret", "registry.py", '"hint": t.get("hint", ""), "agents": list(t["agents"]),', '"hint": t.get("hint", ""), "agents": list(t["agents"]), "s": t["secret"],', "test_registry.py", ["secret_never_in_views"]),
 ("history has no secret", "registry.py", 'changed.append("shared secret")', 'changed.append(f"shared secret {s}")', "test_registry.py test_cluster.py", ["secret_never_in_views", "tenants_and_agents"]),
 ("secret whitespace", "registry.py", "    if s != s.strip():", "    if False:", "test_registry.py", ["lead", "trail"]),
 ("new tenant needs secret", "registry.py", "    if new and not secret_:", "    if False:", "test_registry.py test_cluster.py", ["needs_its_secret", "tenants_and_agents"]),
 ("remove confirm", "registry.py", '    if (confirm or "").strip() != label:', "    if False:", "test_registry.py test_cluster.py", ["typed", "tenants_and_agents"]),
 ("check() tenant keys", "registry.py", "        if key not in TENANTS:\n            raise Invalid(f\"tenants.", "        if False:\n            raise Invalid(f\"tenants.", "test_registry.py", ["malformed_document"]),
 ("host FQDN rule", "registry.py", "len(parts) > 1 and ", "", "test_registry.py", ["[agent-a]"]),
 ("no-op edit", "registry.py", "    if not new and not changed:", "    if False:", "test_registry.py", ["noop"]),
]
bad = 0
for name, f, old, new, tests, expect in M:
    d = Path(tempfile.mkdtemp()) / "t"
    shutil.copytree(SRC, d, ignore=shutil.ignore_patterns("backups", "__pycache__", ".pytest_cache", ".venv"))
    p = d / f
    txt = p.read_text()
    n = txt.count(old)
    if n != 1:
        print(f"!! {name}: pattern matched {n} times — mutation not applied"); bad += 1; continue
    p.write_text(txt.replace(old, new))
    r = subprocess.run([PY, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-rf", *tests.split()], cwd=d,
                       capture_output=True, text=True, timeout=600)
    failed = [l for l in r.stdout.splitlines() if l.startswith("FAILED")]
    hit = [e for e in expect if any(e in l for l in failed)]
    ok = r.returncode != 0 and len(hit) == len(expect)
    bad += not ok
    print(f"{'RED ' if ok else '!!  '} {name:28s} failures={len(failed):2d} expected-hit={len(hit)}/{len(expect)}"
          + ("" if ok else f"\n     missing={sorted(set(expect)-set(hit))}\n     " + "\n     ".join(failed[:6])))
    shutil.rmtree(d.parent)
print("ALL GUARDS SEEN RED" if not bad else f"{bad} GUARD(S) NOT PROVEN")
