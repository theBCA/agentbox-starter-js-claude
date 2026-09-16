FROM python:3.12-alpine@sha256:d09d15e60962ca365d1cd544a48773bac9d33f2fb1b00f2aa0deec78ade7dc31 AS trustgate-python

FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32

# libffi is an Alpine system package (/usr/lib), not a Python package under
# /usr/local. Copy it from the pinned Python Alpine stage so restricted
# dependency-fetch builds do not need direct apk repository access.
COPY --from=trustgate-python /usr/lib/libffi.so.8 /usr/lib/libffi.so.8.2.0 /usr/lib/

COPY --from=trustgate-python /usr/local /usr/local

WORKDIR /app
ENV NODE_ENV=production

COPY package.json package-lock.json* ./
# The npm cache goes, npm itself stays. Deleting npm looks like hardening,
# but TrustGate already governs every runtime install and is the stronger
# control; without npm present its shim just fails in the resolver, so npm
# policy could never be exercised at all.
RUN npm install \
  && rm -rf /root/.npm
COPY src ./src

EXPOSE 8080
# Custom apps run under gVisor, where every cold start pays real import
# overhead. `fetch` pulls in the whole undici stack each time; `net.connect`
# skips it, and a generous timeout keeps a healthy app from flapping.
HEALTHCHECK --interval=10s --timeout=10s --start-period=10s --retries=3 \
  CMD node -e "require('net').createConnection({host:'127.0.0.1',port:8080,timeout:8000}).on('connect',function(){this.end();process.exit(0)}).on('error',function(){process.exit(1)}).on('timeout',function(){process.exit(1)})"
CMD ["node", "src/server.js"]
