# ghidra-rest: a Go REST front end to Ghidra's headless analyzer.
#
# Four stages, same shape as the reference repo (onixldlc/BAR-content-proxy):
#   build     - the server binary for the runtime image
#   distbuild - cross compiled release binaries, exported through `dist`
#   ghidra    - downloads and unpacks Ghidra once, so the runtime layer above
#               it can be rebuilt without re-fetching 540 MiB
#   runtime   - JDK 21 + Ghidra + the server
#
# The runtime image is large and that is inherent: Ghidra ships a full
# analyzer, its sleigh specs and every processor module. Nothing here is
# optional except the docs, which are dropped.

FROM docker.io/library/golang:1.25-alpine AS build

WORKDIR /src

COPY go.mod ./

RUN go mod download

COPY src ./src

ARG VERSION=dev

RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/ghidrarest ./src


# Cross compiled release binaries for every published OS/arch. Kept separate
# from the runtime image on purpose: the mac and windows binaries live in no
# image, and the CI `release` job exports this stage's root with
# `--target dist --output type=local`.
FROM docker.io/library/golang:1.25-alpine AS distbuild

WORKDIR /src

COPY go.mod ./

RUN go mod download

COPY src ./src

COPY docker/build-dist.sh /usr/local/bin/build-dist.sh

ARG VERSION=dev

RUN VERSION="${VERSION}" sh /usr/local/bin/build-dist.sh

# Scratch export target: its whole filesystem is the release binaries and
# nothing else, so `output type=local` lands a clean dist/ dir.
FROM scratch AS dist

COPY --from=distbuild /out/ /


# Ghidra itself. Pinned by version *and* sha256: the release asset is fetched
# over the network at build time, so an unverified download would put whatever
# GitHub served into the image.
FROM docker.io/library/eclipse-temurin:21-jdk-noble AS ghidra

ARG GHIDRA_VERSION=12.1.3

ARG GHIDRA_RELEASE=20260817

ARG GHIDRA_SHA256=93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54

RUN apt-get update

RUN apt-get install -y --no-install-recommends curl unzip ca-certificates

RUN rm -rf /var/lib/apt/lists/*

RUN curl -fsSL -o /tmp/ghidra.zip "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_RELEASE}.zip"

RUN printf '%s  /tmp/ghidra.zip\n' "${GHIDRA_SHA256}" | sha256sum -c -

RUN unzip -q /tmp/ghidra.zip -d /opt

RUN mv "/opt/ghidra_${GHIDRA_VERSION}_PUBLIC" /opt/ghidra

RUN rm -f /tmp/ghidra.zip

# Docs and the bundled Eclipse integration are dead weight for headless use.
RUN rm -rf /opt/ghidra/docs /opt/ghidra/Extensions/Eclipse


FROM docker.io/library/eclipse-temurin:21-jdk-noble AS runtime

# curl is the healthcheck. Everything else Ghidra needs is in the JDK image.
RUN apt-get update

RUN apt-get install -y --no-install-recommends curl ca-certificates

RUN rm -rf /var/lib/apt/lists/*

RUN groupadd -r ghidra

RUN useradd -r -g ghidra -d /opt/ghidra-rest/home -s /usr/sbin/nologin ghidra

COPY --from=ghidra /opt/ghidra /opt/ghidra

COPY --from=build /out/ghidrarest /usr/local/bin/ghidrarest

COPY scripts/ExportJSON.java /opt/ghidra-rest/scripts/ExportJSON.java

COPY scripts/ApplySignature.java /opt/ghidra-rest/scripts/ApplySignature.java

COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh

COPY docker/verify.sh /usr/local/bin/verify.sh

COPY docker/warmup.sh /usr/local/bin/warmup.sh

RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/verify.sh /usr/local/bin/warmup.sh

RUN mkdir -p /data /opt/ghidra-rest/home

RUN chown -R ghidra:ghidra /data /opt/ghidra-rest

ENV HOME=/opt/ghidra-rest/home

ENV GHIDRAREST_ADDR=:8080

ENV GHIDRAREST_DATA_DIR=/data

ENV GHIDRAREST_GHIDRA_HOME=/opt/ghidra

ENV GHIDRAREST_SCRIPT_DIR=/opt/ghidra-rest/scripts

USER ghidra

# Runs the headless analyzer once at build time on a stock system binary.
# This does two things that matter: it fails the build if ExportJSON.java does
# not compile against this Ghidra's API, and it leaves the compiled script in
# $HOME so the first real job does not pay for javac.
RUN /usr/local/bin/warmup.sh

EXPOSE 8080

VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD /usr/local/bin/verify.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
