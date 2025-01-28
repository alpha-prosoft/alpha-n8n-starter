FROM docker.n8n.io/n8nio/n8n

RUN id
RUN node --version

COPY --chown=node:node index.js index.js
COPY --chown=node:node package.json package.json
COPY --chown=node:node package-lock.json package-lock.json
COPY --chown=node:node pnpm-lock.yaml pnpm-lock.yaml

RUN pnpm i --dev

COPY --chown=node:node . .

RUN pnpm run build

RUN ls -la /home/node/dist/

FROM docker.n8n.io/n8nio/n8n

USER root
RUN npm install -g nodemon
USER node

RUN mkdir -p ~/.n8n/custom/
COPY --chmod=755 docker-entrypoint.sh /docker-entrypoint.sh

ENV N8N_CUSTOM_EXTENSIONS=/home/node/.n8n/custom
ENV NODE_FUNCTION_ALLOW_EXTERNAL=*

RUN mkdir -p /home/node/.n8n/custom

COPY --from=0 /home/node/dist  /home/node/.n8n/custom

RUN ls -la ~/.n8n/custom

HEALTHCHECK --interval=30s --timeout=30s --start-period=1m --retries=3 \
    CMD wget -q -O - http://127.0.0.1:5678/healthz || exit 1


