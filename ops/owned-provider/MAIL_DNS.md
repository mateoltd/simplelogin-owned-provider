# Mail and DNS preflight

The preflight performs DNS reads only. It never updates a registrar, DNS
provider, reverse zone, Mailgun account, route, credential, binding, or
production service.

## Managed mail-edge topology

The selected architecture uses managed Mailgun inbound plus Mailgun outbound
behind the independently deployed mail-edge. The old assumption that every
domain points MX at a self-owned inbound MTA and authorizes one self-owned
outbound IP is obsolete for this topology.

Before activating an exact-domain inbound generation, independently capture and
review evidence that:

- the provider account/subaccount and receiving domain are the intended isolated
  resources and the region is correct;
- authoritative MX matches Mailgun's current region-specific receiving records,
  with no unintended lower-priority receiver;
- the exact-domain raw-MIME route points to the TLS hook path containing the
  prepared binding ID and ends in `/raw-mime`;
- the route stops further evaluation and its retry/non-applicable responses have
  been exercised without loops or duplicate product handoff;
- SPF, DKIM, DMARC, return-path/CNAME, and provider-verification records match
  the selected sending configuration and current provider instructions;
- inbound and feedback signatures reach only the intended edge credential
  reference, and outbound SMTP uses the matching domain-scoped credential;
- controlled external receivers prove aligned authentication, envelope/VERP
  correlation, MIME fidelity, and absence of adapter control headers.

Record the authoritative answers, provider domain status, controlled test
results, timestamps, and artifact SHA-256 in the edge capability registry. DNS
presence alone is not qualification.

## Existing helper limitation

`ops/owned-provider/bin/owned-provider dns-preflight` implements the legacy
self-owned-IP model: configured inbound MX hosts, one outbound IP in SPF, a
locally mounted DKIM key, strict DMARC, PTR, and forward-confirmed reverse DNS.
It is still valid only for that contained/legacy topology. It is not a Mailgun
activation check and must not be used as evidence that managed inbound or
outbound is ready.

Likewise, `lifecycle domain-verify` marks only the SimpleLogin-owned domain row.
It neither changes authoritative DNS nor activates an edge route generation.

Mailgun documents its current region-specific API and inbound SMTP endpoints in
its [API overview](https://documentation.mailgun.com/docs/mailgun/api-reference/api-overview).
Always use current provider-generated DNS values for the exact account and
region; do not copy illustrative names or values from this repository.

## Staged DNS change

DNS change remains an external, approved operation:

1. Create prepared inbound and outbound edge generations without traffic.
2. Put them in shadow and complete every exact-domain capability fixture.
3. Lower TTL through the separately approved DNS process and record the prior
   authoritative set. This repository does not perform that change.
4. Activate the intended edge generation, then change only the authorized DNS
   records.
5. Observe controlled inbound, reverse reply, outbound, bounce, complaint,
   unknown, and quarantine paths through multiple TTLs.
6. Drain the old generation. Roll back new traffic explicitly if needed, while
   leaving ambiguous attempts pinned to their original generation.

Never publish provider validation records, MX, SPF, DKIM, CNAME, or DMARC from a
placeholder, personal domain, or unreviewed example.
