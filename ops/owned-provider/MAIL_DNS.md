# Mail and DNS preflight

The preflight performs DNS reads only. It never updates a registrar, DNS
provider, reverse zone, MTA, or production service.

For each operator-owned mail domain it verifies:

- MX contains every configured inbound host.
- One SPF record authorizes the configured outbound IPv4 or IPv6 address.
- `<selector>._domainkey` contains the public key matching the mounted private
  DKIM key.
- DMARC has exactly one record with `p=quarantine` or `p=reject`.
- The outbound address has PTR and forward-confirmed reverse DNS; the optional
  configured PTR host must match.

```sh
export OWNED_PROVIDER_OUTBOUND_IP=203.0.113.10
export OWNED_PROVIDER_PTR_HOST=mx1.example.org
ops/owned-provider/bin/owned-provider dns-preflight mask.example.org
```

The documentation address above is intentionally non-routable and will fail.
Use the deployment's actual public outbound address. A nonzero exit blocks
domain activation. Review all warnings; uncommon SPF `exists`/`ptr` mechanisms
are reported but intentionally not guessed.

Preflight is necessary, not sufficient, for deliverability. The operator still
needs an authenticated production MTA, queue/deferred-mail monitoring, bounce
and complaint handling, IP/domain reputation management, TLS policy, abuse
response, and staged delivery tests to controlled recipients.
