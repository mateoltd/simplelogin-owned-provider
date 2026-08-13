# Mail-edge qualification

The reusable conformance package is documented in
[`../../mail_edge_conformance/README.md`](../../mail_edge_conformance/README.md).
It implements the acceptance gates from
[`MAIL_EDGE_ARCHITECTURE.md`](MAIL_EDGE_ARCHITECTURE.md) without adding a
production edge or changing the selected architecture.

Contained local qualification is available only in test mode:

```sh
ops/owned-provider/bin/owned-provider mail-edge-conformance
```

The command uses the private Compose services `mail-edge-fixture` and
`mail-edge-provider`, records capability evidence beneath the runtime evidence
directory, restores the configured local relay, and stops both fixtures. It
does not touch public DNS, provider accounts, production configuration, or
external recipients.

Live Mailgun qualification is an explicit standalone command with the staging
and credential gates described by the package. Resend and Cloudflare have no
adapter here; the provider-neutral extension contract is ready for a later
implementation and the activation policy treats their missing evidence as a
blocker.
