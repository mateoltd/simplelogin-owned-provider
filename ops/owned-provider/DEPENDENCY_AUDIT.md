# Dependency advisory reachability

This assessment covers the exact `uv.lock` dependency graph and the production
Dockerfile on 2026-08-16 UTC. It is a decision record, not an ignore list. No
`pip-audit` advisory is suppressed.

## Reproducible audit

The pre-change Dockerfile installed the default development group. Its real
image set contained 177 dependencies with 130 advisories in 36 packages. A
`--no-dev` export contained 142 dependencies with 123 advisories in 32
packages. The corrected, upgraded runtime export contains 143 dependencies
with 37 advisories in 8 packages.

```sh
uv export --locked --no-dev --no-emit-project --no-hashes \
  --format requirements-txt --output-file /tmp/owned-provider-requirements.txt
uvx --from 'pip-audit==2.9.0' pip-audit \
  -r /tmp/owned-provider-requirements.txt \
  --no-deps --disable-pip --progress-spinner off --format json
```

`--no-deps` is used only because `uv export` emits the complete locked graph.
The final command exits nonzero while the six recorded packages remain. The
older Rye-generated `requirements*.lock` files are not used by the Dockerfile
or this audit and are not deployment evidence.

## Removed from the production artifact

| Package and advisories | Reachability and disposition |
| --- | --- |
| `black 22.1.0`: PYSEC-2024-48, PYSEC-2026-2120, PYSEC-2026-2121 | Formatter only. Excluded by `uv sync --locked --no-dev`. |
| `pytest 7.0.1`: PYSEC-2026-1845 | Test runner only. Excluded from the image. |
| `tqdm 4.64.0`: PYSEC-2026-1976 | Dev transitive CLI only. Excluded from the image. |
| `virtualenv 20.21.1`: PYSEC-2024-187, PYSEC-2026-2009 | Pre-commit tooling only. Excluded from the image. |

The same build change excludes GPL `pylint` and `djlint` and LGPL `astroid`.
The Docker build now also purges `gcc` and `git` after dependency compilation.

## Upgraded and cleared

Every advisory below was present in the original runtime export and is absent
from the final audit.

| Package, old to new | Advisory IDs | Runtime reachability and deployment exposure |
| --- | --- | --- |
| `aiohttp 3.11.13` to `3.14.3` | PYSEC-2026-1097, 1099, 1100, 1101, 1104, 1105, 1106, 1107, 1109, 237, 2094 through 2113, 3545, 3546, 3547 | No direct import. Present through dormant yacron and the unused Google async transport; no default network path. Lock-only upgrade. |
| `aiosmtpd 1.4.2` to `1.4.6` | PYSEC-2024-221, PYSEC-2026-1111 | The SMTP-smuggling path was exposed by the default inbound listener. STARTTLS is not configured. High-priority lock-only upgrade. |
| `aiosmtplib 1.1.4` to `5.1.1` | PYSEC-2026-2338 | Used only by yacron reporting; yacron is not a default service. Its exercised API remains compatible. |
| `cbor2 5.8.0` to `5.9.0` | PYSEC-2026-2123 | Parses authenticated WebAuthn attestation and was remotely reachable after sudo authorization. Lock-only upgrade. |
| `certifi 2019.11.28` to `2024.7.4` | PYSEC-2022-42986, PYSEC-2023-135, PYSEC-2024-230 | Active outbound TLS trust store. Exposure depended on certificates chaining to removed roots. Lock-only upgrade. |
| `click 8.0.3` to `8.3.3` | PYSEC-2026-2132 | Runtime CLI dependency, but vulnerable `click.edit()` is unused. Lock-only upgrade. |
| `filelock 3.15.4` to `3.20.3` | PYSEC-2026-1374, PYSEC-2026-1375 | Used by tldextract caching. Exploitation required a hostile local process against the private container filesystem. Lock-only upgrade. |
| `flask-cors 3.0.9` to `6.0.0` | PYSEC-2024-71, PYSEC-2024-271, PYSEC-2026-1383, 1384, 1385 | CORS is active on all `/api/*` routes. Uniform API policy removes path-policy confusion, but header behavior was externally reachable. Direct upgrade with API tests. |
| `flask-httpauth 4.1.0` to `4.8.1` | PYSEC-2026-2152 | Only reached through Flask-Profiler, which is disabled in the default deployment. Lock-only upgrade. |
| `gunicorn 20.0.4` to `22.0.0` | PYSEC-2026-1433, PYSEC-2026-1434 | Default public WSGI server behind the operator's reverse proxy. Malformed transfer-encoding forwarding made request smuggling conditionally reachable. Direct upgrade with socket tests. |
| `httplib2 0.22.0` to `0.32.0` | PYSEC-2026-3444 | Google integration transport. Disabled by default without operator credentials; decompression abuse was possible when enabled. Lock-only upgrade. |
| `idna 2.10` to `3.15` | PYSEC-2024-60, PYSEC-2026-215 | Parses user and SMTP-controlled domains. SMTP commands are bounded, but authenticated domain input was a possible CPU sink. Coordinated with Requests. |
| `mako 1.2.4` to `1.3.12` | PYSEC-2026-2617 | Alembic-only templates, repository-controlled paths, Linux deployment. Lock-only upgrade. |
| `protobuf 5.27.1` to `5.29.6` | PYSEC-2026-1805, PYSEC-2026-1806 | CPython wheel backend parses server-owned event data; no external arbitrary protobuf input. Lock-only upgrade. |
| `pyasn1 0.4.8` to `0.6.4` | PYSEC-2026-2263, PYSEC-2026-3455, 3456, 3457 | PGP signature/key DER and optional Google auth. Authenticated PGP input is structurally bounded. Lock-only upgrade. |
| `pycryptodome 3.9.8` to `3.19.1` | PYSEC-2026-1811 | Paddle callback uses PKCS#1 v1.5 verification, not vulnerable OAEP decryption. Paddle is unconfigured by default. Direct upgrade retained callback tests. |
| `pygments 2.7.4` to `2.20.0` | PYSEC-2023-117, PYSEC-2026-2987 | Only IPython and disabled debug-toolbar formatting; no remote lexer input. Lock-only upgrade. |
| `pyjwt 2.4.0` to `2.13.0` | PYSEC-2025-183, PYSEC-2026-120, 175, 177, 179 | Optional phone callback accepts only HS256 with an operator secret. No mixed algorithm or JWK-client path. Lock-only upgrade; the current advisory service no longer flags the package. |
| `python-dotenv 0.14.0` to `1.2.2` | PYSEC-2026-2270 | Startup uses only `load_dotenv`; vulnerable file-writing APIs were unused and the root filesystem is read-only. Direct upgrade. |
| `requests 2.25.1` to `2.33.0` | PYSEC-2023-74, PYSEC-2026-1872, 1873, 2275 | Widely active outbound HTTP. Mail Edge disables environment trust and redirects and keeps TLS verification; optional integrations had conditional proxy/redirect exposure. Direct upgrade with HTTP/Mail Edge tests. |
| `rsa 4.6` to `4.7` | PYSEC-2020-100 | Google Auth pure-Python fallback only; the installed cryptography backend is selected and Google auth is disabled by default. Lock-only upgrade. |
| `setuptools 67.6.0` to `78.1.1` | PYSEC-2025-49, PYSEC-2026-1918 | Packaged for dependencies but no runtime package build/download path. This is the newest fixed line that retains `pkg_resources`, which Flask-Limiter 1.5 imports at startup. |
| `sqlparse 0.4.4` to `0.5.4` | PYSEC-2026-1940, GHSA-27jp-wm6q-gp25 | Disabled debug-toolbar SQL panel only; no attacker-controlled parsing sink. Lock-only upgrade. |
| `urllib3 1.26.20` to `2.7.0` | PYSEC-2026-141, PYSEC-2026-1994, 1996, 1998, 1999 | Active below Requests, Botocore, Sentry, and telemetry. Mail Edge raw downloads already reject encoding and bound bytes, but other peers could trigger decompression work. `newrelic-telemetry-sdk` moved minimally to 0.6.0 to permit the safe urllib3 line. |
| `webob 1.8.7` to `1.8.10` | PYSEC-2024-188, PYSEC-2026-251 | Flanker imports only `MultiDict`; vulnerable redirect normalization is unused. Lock-only upgrade. |

## Remaining findings and release decision

| Package and advisory IDs | Actual reachability and exposure | Why it is not upgraded alone |
| --- | --- | --- |
| `cryptography 37.0.1`: PYSEC-2023-254, PYSEC-2023-11, PYSEC-2026-35, 800, 1283, 1285, 2141, 3553, 3554; GHSA-39hc-v87j-747x, GHSA-5cpq-8wj7-hf2v, GHSA-jm77-qphf-c4w8, GHSA-v8gr-m533-ghj9, GHSA-h4gh-qq45-vh27, GHSA-537c-gmf6-5ccf | Active for AES-GCM/AES-SIV, backup encryption, PGP, JWK, and WebAuthn. No PKCS7, PKCS12, `update_into`, modern verifier, non-prime WebAuthn curve, or TLS-server sink was found. Bundled native OpenSSL remains deployed and cannot be declared unreachable. | `cryptography~=37.0.1` excludes all fixes. A safe change must jointly validate PGPy, old WebAuthn/PyOpenSSL, JWCrypto, FIDO, backup, and Mail Edge cryptography. This blocks a public release. |
| `flask 1.1.2`: PYSEC-2023-62, PYSEC-2026-2151 | Default HTTP runtime. The session access pattern exists; disclosure additionally requires a caching proxy, which default Compose does not provide. | Full fix requires Flask 3.1.3 and coordinated extension-stack modernization. This is part of the public HTTP release blocker. |
| `ipython 7.31.1`: PYSEC-2023-17 | Imported only by operator `shell.py`; no default Compose service starts it. The advisory is Windows/terminal-title specific while production is Linux. | No deployment exposure. Retained for upstream operator compatibility; remove from the runtime dependency group or move to a supported IPython line during dependency restructuring. |
| `jinja2 2.11.3`: PYSEC-2026-1471, 1473, 1474, 1475 | Active for repository-controlled templates. No `xmlattr` use exists; sandboxed newsletter source is administrator-only. | Jinja 3.1 must move with Flask and its extensions. No unprivileged advisory sink was found, but the package remains in the blocked stack. |
| `jwcrypto 0.8`: PYSEC-2024-104, PYSEC-2026-70, PYSEC-2026-827, PYSEC-2026-1484 | OIDC/JWS signing is active. The application does not parse JWE, decompress tokens, auto-detect token types, or invoke the vulnerable verification helpers. | JWCrypto 1.5.7 was tested and rejected during application import because it passes `unsafe_skip_rsa_key_validation`, which cryptography 37 does not support. It must move with the coordinated cryptography upgrade. |
| `pyopenssl 19.1.0`: PYSEC-2026-2268 | Old WebAuthn X.509 verification is active. No SNI callback is registered, so this advisory's sink is absent. | PyOpenSSL 26 requires the coordinated cryptography/WebAuthn upgrade above. |
| `setuptools 78.1.1`: PYSEC-2026-3447 | Runtime packaging APIs are not invoked. This advisory is macOS-specific while the production artifact is Ubuntu Linux. | Setuptools 82 and newer remove `pkg_resources`; 83 was tested and made Flask-Limiter 1.5 fail during application import. Clearing it requires the coordinated Flask extension upgrade, not a compatibility shim. |
| `werkzeug 1.0.1`: PYSEC-2022-203, PYSEC-2023-57, 58, 221, PYSEC-2026-2043, 2044, 2045, 2046, 2320 | Default public HTTP parser. Multipart part-count and long-field denial of service are directly reachable; worker timeouts and memory limits bound but do not eliminate impact. Debugger is off, Windows paths do not apply, and the development-server smuggling report does not describe the Gunicorn path. | Werkzeug cannot safely jump major versions under Flask 1.1.2. Coordinated Flask and extension modernization is required and blocks a public release. |

The security gate therefore has an honest nonzero result: 37 advisories in 8
packages. A release owner may not reinterpret this matrix as an allowlist. The
Flask/Werkzeug and cryptography/PyOpenSSL upgrades need dedicated compatibility
lanes and the same real PostgreSQL, SMTP/socket, OIDC/WebAuthn, backup/restore,
and Mail Edge verification used here.
