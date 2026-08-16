ARG BASE_IMAGE=simplelogin-owned-provider-upstream:local
ARG SOURCE_DATE_EPOCH
FROM ${BASE_IMAGE}
ARG SOURCE_DATE_EPOCH

# Add only the unprivileged runtime identity. The managed interpreter and
# virtual environment are copied into /opt by the root multi-stage build.
RUN test -n "${SOURCE_DATE_EPOCH}" \
    && printf 'simplelogin:x:65532:65532:SimpleLogin runtime:/tmp:/usr/sbin/nologin\n' >> /etc/passwd \
    && printf 'simplelogin:x:65532:\n' >> /etc/group \
    && /opt/venv/bin/python -c 'from flanker.addresslib import address; assert callable(address.parse_list)'
