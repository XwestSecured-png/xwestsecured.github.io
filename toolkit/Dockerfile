# WestGuard container: CLI by default, dashboard with `web`. Runs as a non-root user.
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir "build>=1.2" && python -m build --wheel --outdir /dist

FROM python:3.12-slim
ARG EXTRAS="yara,sigma,stix"
LABEL org.opencontainers.image.title="westguard" \
      org.opencontainers.image.description="Read-only security operations toolkit" \
      org.opencontainers.image.licenses="MIT"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 WESTGUARD_DATA_DIR=/data
RUN groupadd --system --gid 10001 westguard \
 && useradd --system --uid 10001 --gid westguard --home-dir /data --shell /usr/sbin/nologin westguard \
 && mkdir -p /data /work && chown westguard:westguard /data /work
COPY --from=build /dist/*.whl /tmp/
RUN WHL="$(ls /tmp/*.whl)" && pip install --no-cache-dir "${WHL}${EXTRAS:+[$EXTRAS]}" && rm -f /tmp/*.whl
USER 10001:10001
WORKDIR /work
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8765/healthz',timeout=3).status==200 else 1)" || exit 1
ENTRYPOINT ["westguard"]
CMD ["list"]
