# syntax=docker/dockerfile:1.7
# Multi-stage build: web UI → Go binary → minimal non-root runtime image.

FROM node:22-alpine AS web
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM golang:1.26-alpine AS build
WORKDIR /src/backend
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ ./
ARG VERSION=dev
RUN go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/nexus ./cmd/nexus

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/nexus /usr/local/bin/nexus
COPY --from=web /src/frontend/dist /usr/share/nexus/web
ENV NEXUS_LISTEN=:8080 \
    NEXUS_WEB_DIR=/usr/share/nexus/web \
    NEXUS_LOG_FORMAT=json
EXPOSE 8080
USER nonroot:nonroot
HEALTHCHECK NONE
ENTRYPOINT ["/usr/local/bin/nexus"]
CMD ["serve"]
