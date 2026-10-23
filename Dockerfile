FROM node:24-bookworm-slim@sha256:a5f4366e834695d5f363b920c104953a535d3a9864d1bdf74566a0ebe01daee5 AS test
WORKDIR /app
COPY package.json *.mjs ./
COPY public ./public
COPY scripts ./scripts
COPY tests ./tests
COPY README.md DEPLOYMENT.md SECURITY.md SECURITY-PRACTICES.md VERIFICATION.md ./
COPY docs ./docs
RUN node scripts/build.mjs && node --test tests/*.test.mjs

FROM node:24-bookworm-slim@sha256:a5f4366e834695d5f363b920c104953a535d3a9864d1bdf74566a0ebe01daee5 AS runtime
ENV NODE_ENV=production DATABASE_PATH=/data/fingerprints.sqlite PROXY_SOCKET=/run/fingerprint/app.sock
WORKDIR /app
COPY --from=test /app/dist/ ./
RUN mkdir -p /data /backups /run/fingerprint && chown node:node /data /backups /run/fingerprint && chmod 0700 /data /backups && chmod 0770 /run/fingerprint
USER node
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 CMD ["node", "scripts/healthcheck.mjs"]
CMD ["node", "server.mjs"]
