FROM python:3.12.5-slim-bookworm AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SOURCE_DATE_EPOCH=0

WORKDIR /source
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip install --no-cache-dir build==1.2.2.post1 \
    && python -m build --wheel

FROM python:3.12.5-slim-bookworm

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --system --gid 10401 mail-edge \
    && useradd --system --uid 10401 --gid mail-edge --home-dir /nonexistent mail-edge
COPY --from=build /source/dist/*.whl /tmp/mail-edge.whl
RUN python -m pip install --no-cache-dir /tmp/mail-edge.whl \
    && rm /tmp/mail-edge.whl

USER 10401:10401
EXPOSE 2525 8443 9090
ENTRYPOINT ["mail-edge-worker"]
