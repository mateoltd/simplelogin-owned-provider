ARG BASE_IMAGE=simplelogin-owned-provider-upstream:local
FROM ${BASE_IMAGE}

# The qualification kit is an overlay concern and must be present even when the
# pinned upstream image was built from an unchanged source snapshot.
COPY mail_edge_conformance /code/mail_edge_conformance
COPY ops/owned-provider/scripts/mail_edge_e2e.py /code/ops/owned-provider/scripts/mail_edge_e2e.py

# uv installs the pinned interpreter beneath /root and links the virtualenv to
# it. Permit traversal without making /root listable so the runtime can drop
# privileges to the unprivileged UID used by Compose.
RUN printf 'simplelogin:x:65532:65532:SimpleLogin runtime:/tmp:/usr/sbin/nologin\n' >> /etc/passwd \
    && printf 'simplelogin:x:65532:\n' >> /etc/group \
    && chmod 0711 /root \
    && /code/.venv/bin/python -c 'from flanker.addresslib import address; address.parse_list("a@example.com, b@example.com")'
