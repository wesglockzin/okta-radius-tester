# Okta RADIUS Tester

Test an Okta RADIUS integration without the VPN appliance in the loop. The tool sends the
same RADIUS Access-Request a Cisco ASA sends for a VPN client login straight to an Okta
RADIUS Server Agent, and shows what comes back.

## What it does
- **ACCEPT / REJECT / CHALLENGE** with Okta's Reply-Message, per-round timing, and the
  reply attributes. An Access-Challenge (MFA factor choice or a code) is answered on the page.
- **Every reply is verified against the shared secret.** A key mismatch is reported as
  KEY MISMATCH — never folded into REJECT, which is what a wrong key otherwise looks like.
- **One instance for several Okta orgs** (DEV / STG / PROD). Tenants and their agents are
  added on the tool's *Tenants & agents* page: UDP port, shared secret (write-only — never
  shown again), username hint, agents. Every change is listed with who and when; the secret
  never appears in the history.
- The password is sent PAP-hidden with the shared secret and is never stored or logged.

## How the registry is stored
Tenants live in **one Kubernetes Secret** that the pod reads and replaces itself
(`state_store.py`, standard library only):
- the pod's own ServiceAccount gets `get` + `update` on exactly that Secret, nothing else;
- writes are optimistic — a concurrent edit gets HTTP 409 and is refused, never overwritten;
- the Secret is created once, out of band (RBAC cannot scope `create` to one name):

```bash
kubectl create secret generic radius-tester-registry \
  --from-literal=state.json='{"tenants":{},"history":[]}'
```

```yaml
# Role bound to the tool's ServiceAccount; the pod gets FLEET_STATE_SECRET=radius-tester-registry
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["radius-tester-registry"]
    verbs: ["get", "update"]
```

## Run
Kubernetes / OpenShift only: `gunicorn wsgi:app` (see `Dockerfile`, port 8080). The entry
point refuses to start unless the config is complete — an `https://` `APP_BASE_URL`, the
OIDC sign-in (`OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`), `FLASK_SECRET_KEY`,
`FLEET_STATE_SECRET`, and a registry Secret it can read and parse. Each refusal names its
cause. The pod needs UDP to each agent's RADIUS port.

## Tests
```bash
python -m pytest -q test_radius_client.py test_state_store.py test_registry.py test_cluster.py
python mutation_check.py     # each guard must fail against the defect it exists to catch
```
Hermetic: a loopback fake RADIUS agent and a loopback fake Kubernetes API — no Okta, agent
or cluster is contacted.

## Stack
Python 3 · Flask · gunicorn · Authlib (OIDC sign-in). The RADIUS client is standard library
only (RFC 2865 PAP + Access-Challenge, RFC 2869 Message-Authenticator).

## Known limitations
- **The org URLs are constants.** The sign-in issuer (`_bootstrap.py`) and the three tenant
  org URLs (`registry.py`) must be set to your own orgs.
- **One RADIUS app per tenant**, and tenants are limited to DEV / STG / PROD.
- **PAP only** — no CHAP or EAP.
- **One gunicorn worker**: a pending Access-Challenge must be answered by the same process.
- **No local entry point.** It is built to run in a cluster; `app.py` imports outside one
  (with an in-memory registry) for the tests.
- A wrong password counts toward that account's directory lockout — test with a test
  account, or a username that does not exist to check the path and the key.
