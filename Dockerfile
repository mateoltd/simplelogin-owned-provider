# syntax=docker/dockerfile:1.7

ARG NODE_IMAGE="node:24.19.0-alpine@sha256:d32cdf619f63fe0471182d08996dd516c6275bb5fd31ae06e55a570bd9e1ad43"
ARG UBUNTU_IMAGE="ubuntu:22.04@sha256:3b06811b2afd352be909dd088a004166d665dc76d38b13eada33522a9d915c6f"

FROM --platform=linux/amd64 ${NODE_IMAGE} AS frontend
WORKDIR /code/static
COPY static/package.json static/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund \
    && ./node_modules/.bin/esbuild \
        --bundle \
        --global-name=Sentry \
        --minify \
        --outfile=/code/static/sentry.bundle.min.js \
        node_modules/@sentry/browser/build/npm/esm/prod/index.js \
    && npm prune --omit=dev --ignore-scripts --no-audit --no-fund \
    && test ! -e node_modules/esbuild \
    && test ! -e node_modules/.bin/esbuild

FROM --platform=linux/amd64 ${UBUNTU_IMAGE} AS python-builder

ARG UBUNTU_SNAPSHOT="20260731T000000Z"
ARG UV_VERSION="0.10.12"
ARG UV_HASH="ec72570c9d1f33021aa80b176d7baba390de2cfeb1abcbefca346d563bf17484"

ENV DEBIAN_FRONTEND=noninteractive \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_PYTHON_INSTALL_DIR=/opt/uv-python

WORKDIR /build
COPY pyproject.toml uv.lock .python-version ./

RUN --mount=from=frontend,source=/etc/ssl/certs/ca-certificates.crt,target=/tmp/bootstrap-ca.crt,ro \
    install -D -m 0644 /tmp/bootstrap-ca.crt /etc/ssl/certs/ca-certificates.crt \
    && sed -i "s/^deb /deb [snapshot=${UBUNTU_SNAPSHOT}] /" /etc/apt/sources.list \
    && apt-get -o APT::Update::Error-Mode=any update \
    && apt-get install -y --no-install-recommends \
        build-essential ca-certificates curl libpq-dev libre2-dev \
    && curl --fail --location --show-error --silent \
        "https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/uv-x86_64-unknown-linux-gnu.tar.gz" \
        --output /tmp/uv.tar.gz \
    && echo "${UV_HASH}  /tmp/uv.tar.gz" | sha256sum -c - \
    && tar --extract --gzip --file /tmp/uv.tar.gz --directory /tmp \
    && install -m 0755 /tmp/uv-x86_64-unknown-linux-gnu/uv /usr/local/bin/uv \
    && uv python install "$(cat .python-version)" \
    && uv sync --locked --no-dev --no-install-project \
    && python_root="/opt/uv-python/cpython-$(cat .python-version)-linux-x86_64-gnu" \
    && rm -rf \
        "$python_root/lib/itcl4.3.5" \
        "$python_root/lib/tcl9" \
        "$python_root/lib/tcl9.0" \
        "$python_root/lib/thread3.0.4" \
        "$python_root/lib/tk9.0" \
        "$python_root/lib/libtcl9.0.so" \
        "$python_root/lib/libtcl9tk9.0.so" \
        "$python_root/lib/python3.12/idlelib" \
        "$python_root/lib/python3.12/tkinter" \
        "$python_root/lib/python3.12/turtledemo" \
        "$python_root/lib/python3.12/lib-dynload/_tkinter.cpython-312-x86_64-linux-gnu.so" \
        "$python_root/include" \
        "$python_root/lib/python3.12/ensurepip" \
        "$python_root/lib/python3.12/lib2to3" \
        "$python_root/lib/python3.12/pydoc_data" \
        "$python_root/lib/python3.12/venv" \
        "$python_root/lib/python3.12/site-packages/pip" \
        "$python_root/lib/python3.12/site-packages/pip-26.0.1.dist-info" \
    && rm -f \
        "$python_root/bin/2to3" \
        "$python_root/bin/2to3-3.12" \
        "$python_root/bin/idle3" \
        "$python_root/bin/idle3.12" \
        "$python_root/bin/pip" \
        "$python_root/bin/pip3" \
        "$python_root/bin/pip3.12" \
        "$python_root/bin/pydoc3" \
        "$python_root/bin/pydoc3.12" \
        "$python_root/bin/python3-config" \
        "$python_root/bin/python3.12-config" \
        "$python_root/lib/python3.12/pydoc.py" \
    && test -z "$(find "$python_root" \
        \( -name '_tkinter*.so' -o -name 'libtcl9*.so' -o -name 'pip' \
        -o -name 'pip3' -o -name 'pip3.12' -o -name 'ensurepip' \
        -o -name 'Python.h' \) -print -quit)" \
    && find /opt/venv -type d -name __pycache__ -prune -exec rm -rf {} + \
    && find /opt/venv -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete \
    && rm -rf /root/.cache /tmp/uv*

FROM --platform=linux/amd64 ${UBUNTU_IMAGE} AS runtime

ARG UBUNTU_SNAPSHOT="20260731T000000Z"
ARG OWNED_PROVIDER_SOURCE_COMMIT
ARG SIMPLELOGIN_UPSTREAM_COMMIT
ARG SOURCE_DATE_EPOCH

ENV DEBIAN_FRONTEND=noninteractive \
    PATH=/opt/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

LABEL org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.source="https://github.com/mateoltd/simplelogin-owned-provider" \
      org.opencontainers.image.upstream.source="https://github.com/simple-login/app" \
      org.opencontainers.image.revision="${OWNED_PROVIDER_SOURCE_COMMIT}" \
      org.opencontainers.image.upstream.revision="${SIMPLELOGIN_UPSTREAM_COMMIT}" \
      org.opencontainers.image.source-date-epoch="${SOURCE_DATE_EPOCH}"

RUN --mount=from=frontend,source=/etc/ssl/certs/ca-certificates.crt,target=/tmp/bootstrap-ca.crt,ro \
    install -D -m 0644 /tmp/bootstrap-ca.crt /etc/ssl/certs/ca-certificates.crt \
    && sed -i "s/^deb /deb [snapshot=${UBUNTU_SNAPSHOT}] /" /etc/apt/sources.list \
    && apt-get -o APT::Update::Error-Mode=any update \
    && apt-get install -y --no-install-recommends \
        bash ca-certificates gnupg libre2-9 libpq5 tar \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/* /var/cache/debconf/*

COPY --from=python-builder /opt/uv-python /opt/uv-python
COPY --from=python-builder /opt/venv /opt/venv

WORKDIR /code
COPY LICENSE ./LICENSE
COPY app ./app
COPY commands ./commands
COPY events ./events
COPY migrations ./migrations
COPY monitor ./monitor
COPY tasks ./tasks
COPY templates ./templates
COPY static ./static
COPY local_data/paddle.key.pub ./local_data/paddle.key.pub
COPY local_data/words.txt ./local_data/words.txt
COPY alembic.ini cron.py email_handler.py event_listener.py init_app.py \
    job_runner.py maintenance_app.py monitoring.py newrelic.ini server.py \
    simplelogin_app.py wsgi.py ./
COPY ops/owned-provider/entrypoint.sh ./ops/owned-provider/entrypoint.sh
COPY ops/owned-provider/migrations ./ops/owned-provider/migrations
COPY ops/owned-provider/scripts ./ops/owned-provider/scripts
COPY ops/owned-provider/UPSTREAM_COMMIT ./ops/owned-provider/UPSTREAM_COMMIT
COPY --from=frontend /code/static/node_modules /code/static/node_modules
COPY --from=frontend /code/static/sentry.bundle.min.js /code/static/sentry.bundle.min.js

RUN test -n "${OWNED_PROVIDER_SOURCE_COMMIT}" \
    && test -n "${SIMPLELOGIN_UPSTREAM_COMMIT}" \
    && test -n "${SOURCE_DATE_EPOCH}" \
    && printf 'SHA1 = "%s"\nBUILD_TIME = "%s"\nVERSION = SHA1\n' \
        "${OWNED_PROVIDER_SOURCE_COMMIT}" "${SOURCE_DATE_EPOCH}" \
        > /code/app/build_info.py \
    && mkdir -p /code/static/upload \
    && test -d /code/commands \
    && test -d /code/events \
    && test -d /code/monitor \
    && test -d /code/tasks \
    && test -d /code/ops/owned-provider/migrations \
    && test -s /code/local_data/paddle.key.pub \
    && test -s /code/ops/owned-provider/UPSTREAM_COMMIT \
    && test ! -e /code/.owned-provider \
    && test ! -e /code/tests \
    && test ! -e /code/local_data/private-pgp.asc \
    && test ! -e /code/local_data/public-pgp.asc \
    && test ! -e /code/local_data/jwtRS256.key \
    && test ! -e /code/local_data/jwtRS256.key.pub \
    && test ! -e /code/local_data/key.pem \
    && test ! -e /code/local_data/cert.pem \
    && test ! -e /code/local_data/dkim.key \
    && test ! -e /code/local_data/dkim.pub.key \
    && test ! -e /code/local_data/email_tests \
    && test ! -e /code/local_data/test_words.txt \
    && test -z "$(find /code/static/upload -mindepth 1 -print -quit)"

EXPOSE 7777
CMD ["gunicorn", "wsgi:app", "-b", "0.0.0.0:7777", "-w", "2", "--timeout", "15"]
