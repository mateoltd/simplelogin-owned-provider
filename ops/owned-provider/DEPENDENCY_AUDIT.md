# Dependency advisory reachability

This assessment covers the exact `uv.lock` dependency graph and the production
Dockerfile on 2026-08-16 UTC. It is a decision record, not an ignore list. No
`pip-audit` advisory is suppressed.

## Reproducible audit

The pre-change Dockerfile installed the default development group. Its real
image set contained 177 dependencies with 130 advisories in 36 packages. A
`--no-dev` export contained 142 dependencies with 123 advisories in 32
packages. The first corrected runtime export contained 143 dependencies with
37 advisories in 8 packages. The coordinated migration in this branch contains
115 runtime dependencies and reports zero known Python advisories. The exact
production npm lock also reports zero known advisories.

```sh
uv export --locked --no-dev --no-emit-project --no-editable --no-hashes \
  --format requirements-txt --output-file /tmp/owned-provider-requirements.txt
uvx --from 'pip-audit==2.9.0' pip-audit \
  -r /tmp/owned-provider-requirements.txt \
  --no-deps --disable-pip --progress-spinner off --format json
(cd static && npm audit --package-lock-only)
```

`--no-deps` is used only because `uv export` emits the complete locked graph.
The audit does not ignore or suppress any finding. The older Rye-generated
`requirements*.lock` files are not used by the Dockerfile or this audit and
are not deployment evidence.

The client audit additionally found three findings in the base lock: Sentry's
prototype-pollution gadget, Bootbox's confirmation-dialog XSS, and Vue 2's
HTML-parser ReDoS. Their browser paths are active. They were migrated to
`@sentry/browser 10.70.0`, `bootbox 6.0.4`, and `vue 3.5.41`; the final npm
audit reports zero findings. Sentry is bundled in the pinned frontend stage,
Vue call sites use the Vue 3 application API, and the build-only bundler is
pruned before the runtime layer is copied.

## Removed from the production artifact

| Package and advisories | Reachability and disposition |
| --- | --- |
| `black 22.1.0`: PYSEC-2024-48, PYSEC-2026-2120, PYSEC-2026-2121 | Formatter only. Excluded by `uv sync --locked --no-dev`. |
| `pytest 7.0.1`: PYSEC-2026-1845 | Test runner only. Excluded from the image. |
| `tqdm 4.64.0`: PYSEC-2026-1976 | Dev transitive CLI only. Excluded from the image. |
| `virtualenv 20.21.1`: PYSEC-2024-187, PYSEC-2026-2009 | Pre-commit tooling only. Excluded from the image. |

The same build change excludes GPL `pylint` and `djlint`, LGPL `astroid`, and
the runtime-unused `memory-profiler`. The multi-stage Docker build keeps
compilers, Git, uv, npm, and other build tooling outside the runtime stage.

## Upgraded and cleared

Every advisory below was present in the original runtime export and is absent
from the final audit.

| Package, old to new | Advisory IDs | Runtime reachability and deployment exposure |
| --- | --- | --- |
| `aiohttp 3.11.13` to `3.14.3` | PYSEC-2026-1097, 1099, 1100, 1101, 1104, 1105, 1106, 1107, 1109, 237, 2094 through 2113, 3545, 3546, 3547 | No direct import. Present through dormant yacron and the unused Google async transport; no default network path. Lock-only upgrade. |
| `aiosmtpd 1.4.2` to `1.4.6` | PYSEC-2024-221, PYSEC-2026-1111 | The SMTP-smuggling path was exposed by the default inbound listener. STARTTLS is not configured. High-priority lock-only upgrade. |
| `aiosmtplib 1.1.4` to `5.1.2` | PYSEC-2026-2338 | Used only by yacron reporting; yacron is not a default service. Its exercised API remains compatible. |
| `cbor2 5.8.0` to `6.1.4` | PYSEC-2026-2123 | Parses authenticated WebAuthn attestation and was remotely reachable after sudo authorization. Direct upgrade with real ceremony and X.509 tests. |
| `certifi 2019.11.28` to `2026.7.22` | PYSEC-2022-42986, PYSEC-2023-135, PYSEC-2024-230 | Active outbound TLS trust store. Exposure depended on certificates chaining to removed roots. Lock-only upgrade. |
| `click 8.0.3` to `8.4.2` | PYSEC-2026-2132 | Runtime CLI dependency, but vulnerable `click.edit()` is unused. Lock-only upgrade. |
| `filelock 3.15.4` to `3.32.3` | PYSEC-2026-1374, PYSEC-2026-1375 | Used by tldextract caching. Exploitation required a hostile local process against the private container filesystem. Lock-only upgrade. |
| `flask-cors 3.0.9` to `6.0.5` | PYSEC-2024-71, PYSEC-2024-271, PYSEC-2026-1383, 1384, 1385 | CORS is active on all `/api/*` routes. Uniform API policy removes path-policy confusion, but header behavior was externally reachable. Direct upgrade with API tests. |
| `flask-httpauth 4.1.0` removed | PYSEC-2026-2152 | Reached only through Flask-Profiler, which moved to the explicit operator extra. Neither distribution is present in the default production export. |
| `gunicorn 20.0.4` to `26.0.0` | PYSEC-2026-1433, PYSEC-2026-1434 | Default public WSGI server behind the operator's reverse proxy. Malformed transfer-encoding forwarding made request smuggling conditionally reachable. Direct upgrade with socket tests. |
| `httplib2 0.22.0` to `0.32.0` | PYSEC-2026-3444 | Google integration transport. Disabled by default without operator credentials; decompression abuse was possible when enabled. Lock-only upgrade. |
| `idna 2.10` to `3.18` | PYSEC-2024-60, PYSEC-2026-215 | Parses user and SMTP-controlled domains. SMTP commands are bounded, but authenticated domain input was a possible CPU sink. Coordinated with Requests. |
| `mako 1.2.4` to `1.4.1` | PYSEC-2026-2617 | Alembic-only templates, repository-controlled paths, Linux deployment. Lock-only upgrade. |
| `protobuf 5.27.1` to `7.35.1` | PYSEC-2026-1805, PYSEC-2026-1806 | CPython wheel backend parses server-owned event data; no external arbitrary protobuf input. Lock-only upgrade. |
| `pyasn1 0.4.8` to `0.6.4` | PYSEC-2026-2263, PYSEC-2026-3455, 3456, 3457 | PGP signature/key DER and optional Google auth. Authenticated PGP input is structurally bounded. Lock-only upgrade. |
| `pycryptodome 3.9.8` to `3.19.1` | PYSEC-2026-1811 | Paddle callback uses PKCS#1 v1.5 verification, not vulnerable OAEP decryption. Paddle is unconfigured by default. Direct upgrade retained callback tests. |
| `pygments 2.7.4` removed | PYSEC-2023-117, PYSEC-2026-2987 | Reached only through IPython and debug-toolbar formatting. Both moved to the explicit operator extra and are absent from the default production export. |
| `pyjwt 2.4.0` to `2.13.0` | PYSEC-2025-183, PYSEC-2026-120, 175, 177, 179 | Optional phone callback accepts only HS256 with an operator secret. No mixed algorithm or JWK-client path. Lock-only upgrade; the current advisory service no longer flags the package. |
| `python-dotenv 0.14.0` to `1.2.2` | PYSEC-2026-2270 | Startup uses only `load_dotenv`; vulnerable file-writing APIs were unused and the root filesystem is read-only. Direct upgrade. |
| `requests 2.25.1` to `2.33.1` | PYSEC-2023-74, PYSEC-2026-1872, 1873, 2275 | Widely active outbound HTTP. Mail Edge disables environment trust and redirects and keeps TLS verification; optional integrations had conditional proxy/redirect exposure. Direct upgrade with HTTP/Mail Edge tests. |
| `rsa 4.6` removed | PYSEC-2020-100 | The old Google Auth pure-Python fallback left the current runtime graph; Google integration uses its supported cryptography backend and remains disabled without operator credentials. |
| `setuptools 67.6.0` removed | PYSEC-2025-49, PYSEC-2026-1918 | Flask-Limiter 4 no longer imports `pkg_resources`, and the source-built runtime installs no package manager or build backend. |
| `sqlparse 0.4.4` removed | PYSEC-2026-1940, GHSA-27jp-wm6q-gp25 | It was reachable only through the optional debug-toolbar SQL panel, which is absent from the default production export. |
| `urllib3 1.26.20` to `2.7.0` | PYSEC-2026-141, PYSEC-2026-1994, 1996, 1998, 1999 | Active below Requests, Botocore, Sentry, and telemetry. Mail Edge raw downloads already reject encoding and bound bytes, but other peers could trigger decompression work. `newrelic-telemetry-sdk` moved minimally to 0.6.0 to permit the safe urllib3 line. |
| `webob 1.8.7` to `1.8.11` | PYSEC-2024-188, PYSEC-2026-251 | Flanker imports only `MultiDict`; vulnerable redirect normalization is unused. Lock-only upgrade. |

## Coordinated closure of the remaining 37 findings

These findings were all present at exact base commit
`7e416296bb968d734b4718cdffa528d2949397f9`. None is classified as unreachable
in the final artifact; every affected distribution was upgraded or removed
from the runtime graph.

| Distribution | Base findings | Final disposition and exercised runtime path |
| --- | ---: | --- |
| `cryptography 37.0.1` | 15 | Upgraded to `50.0.0` with PyOpenSSL 26, WebAuthn 3, JWCrypto 1.5, PGP, backup encryption, JWK, and Mail Edge crypto compatibility migrations. |
| `Flask 1.1.2` | 2 | Upgraded to `3.1.3`; session cookie, login activity, Flask-Admin, limiter, and blueprint APIs were migrated. |
| `IPython 7.31.1` | 1 | Removed from the production dependency group. Supported `9.16.1` remains an explicit operator-only extra and is absent from the default OCI install. |
| `Jinja2 2.11.3` | 4 | Upgraded to `3.1.6` with the Flask template paths retained. |
| `JWCrypto 0.8` | 4 | Upgraded to `1.5.8`; public JWK export APIs replace private calls and verification explicitly permits only `RS256` JWS objects. |
| `PyOpenSSL 19.1.0` | 1 | Upgraded to `26.4.0` with WebAuthn 3 registration and assertion verification. |
| `setuptools 78.1.1` | 1 | Removed from the production export after Flask-Limiter 4 eliminated the old `pkg_resources` dependency. It may exist only in the development environment. |
| `Werkzeug 1.0.1` | 9 | Upgraded to `3.1.8`; parser and multipart limits remain fail-closed behind Gunicorn and bounded container resources. |

Total before: 37. Total after: 0. The machine-readable post-change result is
produced by the command above and covers the complete locked runtime export.

The opaque `sl-pgp 0.1.1` wheel was also removed: its public repository
contains only a placeholder README and provides neither corresponding source
nor license metadata for the released native binaries. The reusable PGP path
now uses source-available PGPy, while the default GnuPG path and armored-message
compatibility remain intact. `psycopg2-binary` was replaced with a source-built
`psycopg2 2.9.12` extension dynamically linked to the image's inventoried
`libpq`, so the native closure is visible and reproducible.
