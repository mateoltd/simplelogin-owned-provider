# Local enrollment and system mail

Use a disposable database, Redis and a local SMTP sink to develop the public SimpleLogin API.
Each product user needs an independent account and verified destination mailbox. The bootstrap
operator is not a shared client identity. Client requests use `Authentication: <user-api-key>`;
Mail Edge operator and tenant credentials stay on the server.

The contained Compose configuration closes public registration. In an isolated, loopback-only
**nonproduction** instance, registration can instead use the existing upstream API by leaving
`DISABLE_REGISTRATION` unset. This is a local runtime configuration choice, not a production default.

1. Run the current Alembic migrations and `init_app.py` against fresh services. Run
   `ops/owned-provider/scripts/ops_migrate.py` for the operational schema.
2. Configure `POSTFIX_SERVER` and `POSTFIX_PORT` to the local sink only. System notifications use
   SMTP even when alias transport uses Mail Edge. Generate disposable DKIM and application secrets;
   DKIM requires an RSA private key in the format accepted by the installed DKIM library (PKCS#1).
3. Register with `POST /api/auth/register` using `{email,password}`. Before activation, login must
   return 422. Read the code from the local sink and call `POST /api/auth/activate` with `{email,code}`.
4. Call `POST /api/auth/login` with `{email,password,device}`. Preserve its existing MFA behavior.
   Store each returned API key privately and inspect `GET /api/mailboxes` for that user's destination.
5. Exercise alias creation and ownership denial using two users. Never share the administrator key.

Upstream `email-validator` rejects special-use `.test` email domains. The contained configuration
uses `aliases.example.com` for aliases. Mailbox validation also performs real MX checks; retain those
checks. The existing contained E2E convention uses unique synthetic addresses at `gmail.com` while
all SMTP goes exclusively to the local sink. A received local verification code demonstrates the
local enrollment/mailbox workflow, **not** possession of an external inbox or Internet delivery.
Never carry those synthetic accounts or temporary keys into production.

## Resource preflight

CPU quota support and a sustained stress receipt do not alone establish isolation. Check memory and
process limits, non-root identity, read-only application/root mounts, namespace separation,
no-new-privileges, capability removal, syscall confinement and loopback-only published endpoints.
Do not remove required confinement or modify the system-wide Docker daemon to make a test pass.

If Docker reports missing cgroup controls, the installed systemd user manager and bubblewrap can
provide a disposable development runtime where supported by the host:

- Export pinned local OCI root filesystems without starting their containers. Keep exact image/source
  identities and any read-only current-source overlay explicit; this is not a newly built OCI image.
- Place the supervisor and all services under a dedicated user unit with finite `MemoryMax`,
  `TasksMax`, `LimitNOFILE`, `NoNewPrivileges=yes` and a restrictive `UMask`.
- Run each service through bubblewrap with separate user/PID/IPC/UTS namespaces, all capabilities
  dropped, read-only root/source, private temporary storage and only its own data/secret mounts.
  Load an application seccomp filter after sandbox construction; reject namespace/mount, kernel
  administration, tracing, keyring and raw-I/O operations not needed by the application.
- Bind HTTP, SMTP, PostgreSQL, Redis and the sink UI exclusively to loopback. Keep secrets and sink
  contents private. Inspect the actual service processes' cgroup limits, capability mask,
  `NoNewPrivs` and `Seccomp`, rather than trusting only configuration text.
- Stop the task-owned unit to stop the lab. Preserve or remove only its disposable data according to
  the collaborating sessions' ownership agreement.

This alternative is for local development. It does not qualify production resource capacity,
public HTTPS, live provider delivery, external DNS ownership or off-host recovery. Production keeps
the existing contained deployment and audit requirements.
