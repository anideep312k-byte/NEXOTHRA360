FROM python:3.12-alpine AS builder
WORKDIR /build
RUN apk add --no-cache gcc musl-dev libffi-dev postgresql-dev
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

FROM python:3.12-alpine AS runtime
RUN apk add --no-cache libpq libstdc++ ca-certificates tini wget && \
    addgroup -g 10001 -S kavach && \
    adduser -u 10001 -S kavach -G kavach
WORKDIR /app
COPY --from=builder /root/.local /home/kavach/.local
COPY --chown=kavach:kavach . /app
ENV PATH="/home/kavach/.local/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    APP_ENV=production
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/api/health || exit 1
ENTRYPOINT ["/sbin/tini","--","gunicorn","-c","deploy/gunicorn.conf.py","kavach360.web.app:create_app()"]
