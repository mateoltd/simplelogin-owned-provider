ARG BASE_IMAGE=simplelogin-owned-provider-upstream:local
FROM ${BASE_IMAGE}

# uv installs the pinned interpreter beneath /root and links the virtualenv to
# it. Permit traversal without making /root listable so the runtime can drop
# privileges to the unprivileged UID used by Compose.
RUN printf 'simplelogin:x:65532:65532:SimpleLogin runtime:/tmp:/usr/sbin/nologin\n' >> /etc/passwd \
    && printf 'simplelogin:x:65532:\n' >> /etc/group \
    && chmod 0711 /root \
    && /code/.venv/bin/python -c 'from flanker.addresslib import address; address.parse_list("a@example.com, b@example.com")'
