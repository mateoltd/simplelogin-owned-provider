ARG BASE_IMAGE=simplelogin-owned-provider-upstream:local
FROM ${BASE_IMAGE}

# Add only the unprivileged runtime identity. The managed interpreter and
# virtual environment are copied into /opt by the root multi-stage build.
RUN printf 'simplelogin:x:65532:65532:SimpleLogin runtime:/tmp:/usr/sbin/nologin\n' >> /etc/passwd \
    && printf 'simplelogin:x:65532:\n' >> /etc/group \
    && /opt/venv/bin/python -c 'from flanker.addresslib import address; assert callable(address.parse_list)'
