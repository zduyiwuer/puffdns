# puffdns — self-hosted DNS server with a web panel
#
# Node has no runtime dependencies, so there is no build step and no
# node_modules layer: the image is just the source plus a base runtime.

FROM node:22-alpine

LABEL org.opencontainers.image.title="puffdns" \
      org.opencontainers.image.description="Authoritative DNS + forwarding resolver with web management panel" \
      org.opencontainers.image.licenses="MIT"

# tini gives us correct signal handling so SIGTERM reaches node and the
# store gets flushed on `docker stop`.
RUN apk add --no-cache tini

ENV NODE_ENV=production \
    PUFFDNS_DATA=/data \
    DNS_PORT=53 \
    WEB_PORT=8080

WORKDIR /app

COPY package.json ./
COPY src ./src
COPY public ./public

# /data holds puffdns.json and the session secret; mount a volume here.
RUN mkdir -p /data && chown -R node:node /data /app

USER node

VOLUME ["/data"]

# 53/tcp+udp for DNS, 8080/tcp for the panel and the DoH endpoint
EXPOSE 53/tcp 53/udp
EXPOSE 8080/tcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://127.0.0.1:'+(process.env.WEB_PORT||8080)+'/api/health',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "src/index.js"]
