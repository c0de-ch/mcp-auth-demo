# mcp-auth-demo — run any example server from a container.
#
#   docker run --rm -p 4104:4104 -e PUBLIC_HOST=192.168.1.10 \
#     ghcr.io/c0de-ch/mcp-auth-demo:latest ex:04:server
#
# PUBLIC_HOST must be the address other machines (and Keycloak) use to reach the
# host — inside a container auto-detection would pick the container's own IP.
# Keycloak is expected at http://$PUBLIC_HOST:8180 (override with KEYCLOAK_URL).
FROM node:22-alpine

WORKDIR /app
ENV NODE_ENV=production \
    MCP_LOG=1

# dependencies first (layer cache); tsx/typescript are dev deps but needed to run .ts
COPY package.json package-lock.json ./
RUN npm ci --include=dev && npm cache clean --force

COPY . .

# example servers 4100-4111, gateway internal 4119, downstream API 4190, local issuer 4192
EXPOSE 4100-4111 4119 4190 4192

USER node
ENTRYPOINT ["npm", "run", "--silent"]
CMD ["ex:00:server"]
