# Network Atlas — containerised scanner and viewer.
#
# IMPORTANT: this image only does its job with `--network host`.
#
# Network Atlas discovers devices by ARP scanning, by listening for broadcast
# discovery traffic (mDNS, DHCP, SSDP, NetBIOS, LLDP, CDP) and by reading the
# kernel neighbour table. A container on Docker's default bridge network sits
# behind NAT on its own layer-2 segment, so none of that reaches it: it would
# discover the bridge gateway and nothing else. Sharing the host's network
# namespace is not an optimisation here, it is the difference between working
# and returning an empty map.
#
# See docker-compose.yml, or https://github.com/ShortPlanet3058/network-atlas/wiki/Docker for the full explanation.

# Kali, not Debian: `exploitdb` -- the offline exploit database the audit
# correlates against -- is a Kali package with no Debian equivalent, and the same
# is true of several other tools here. Kali is also what the project targets.
FROM kalilinux/kali-rolling

# Keep the layer cache useful and the image reproducible-ish.
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NETWORK_ATLAS_DB=/data/atlas.db

# Runtime tools, grouped by what they are for. Nothing here is a build
# dependency: the application is pure standard-library Python.
# wireshark-common asks whether non-root users may capture. Preseeded
# so the build is not silently answered "no" by the noninteractive frontend --
# the capabilities set further down are what actually grant it, but the answer
# also decides dumpcap's file mode.
RUN echo "wireshark-common wireshark-common/install-setuid boolean true" \
        | debconf-set-selections

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        iproute2 \
        ca-certificates \
        libcap2-bin \
        # active discovery and service/OS fingerprinting
        nmap \
        arp-scan \
        # passive discovery: tshark drives it, dumpcap does the capturing
        tshark \
        # name resolution
        nbtscan \
        dnsutils \
        avahi-utils \
        # passive OS fingerprinting
        p0f \
        # the audit: offline exploit correlation and TLS posture
        exploitdb \
        sslscan \
        # identifies appliances from their web interface, which is often the only
        # place a model number is written down
        whatweb \
        # optional: managed-switch topology over read-only SNMP
        snmp \
    && rm -rf /var/lib/apt/lists/*

# Nmap's raw-packet modes and packet capture normally need root. Granting the
# capabilities to the binaries instead lets the application run unprivileged,
# which is how it behaves on Kali -- and its capability probe detects this
# rather than assuming a UID.
# Only the capabilities the work actually needs. Granting cap_net_bind_service
# as Kali's own packaging does would make nmap unexecutable here: if a file's
# permitted set contains a capability outside the container's bounding set,
# execve fails with EPERM before the program ever runs.
RUN setcap cap_net_raw,cap_net_admin+eip /usr/lib/nmap/nmap \
    && setcap cap_net_raw,cap_net_admin+eip /usr/bin/dumpcap \
    && setcap cap_net_raw,cap_net_admin+eip /usr/sbin/arp-scan \
    && chmod 0755 /usr/bin/dumpcap

# An unprivileged account owning the state directory. Scanning does not need
# root here, so it does not get it.
RUN useradd --create-home --shell /usr/sbin/nologin --uid 10001 atlas \
    && mkdir -p /data \
    && chown atlas:atlas /data

WORKDIR /app
COPY --chown=atlas:atlas network_atlas/ ./network_atlas/
COPY --chown=atlas:atlas README.md PRIVACY.md ./

USER atlas
VOLUME ["/data"]
EXPOSE 8765

# The viewer refuses a non-loopback bind without --allow-remote because it has
# no authentication. Inside a container the port is only reachable through the
# host's own networking, so binding 0.0.0.0 is the intended configuration --
# publish it to 127.0.0.1 on the host, as the compose file does.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/api/summary', timeout=4)"

ENTRYPOINT ["python3", "-m", "network_atlas"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8765", "--allow-remote"]

# Standard OCI annotations, declared last so editing them does not invalidate the
# package layers above. Without these the image inherits Kali's base-image labels
# and appears on a registry as Kali's own work rather than this project's.
LABEL org.opencontainers.image.title="Network Atlas" \
      org.opencontainers.image.description="Local network discovery, topology mapping and security findings" \
      org.opencontainers.image.source="https://github.com/ShortPlanet3058/network-atlas" \
      org.opencontainers.image.documentation="https://github.com/ShortPlanet3058/network-atlas/wiki" \
      org.opencontainers.image.url="https://github.com/ShortPlanet3058/network-atlas" \
      org.opencontainers.image.vendor="ShortPlanet3058" \
      org.opencontainers.image.authors="ShortPlanet3058" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.base.name="docker.io/kalilinux/kali-rolling"

# The base image sets its own created and revision labels, and LABEL inherits
# anything not overridden. Left alone, this image reports Kali's build date and
# Kali's git revision as its own, which misstates where it came from to anyone
# reading its provenance. Defaults are honest placeholders rather than a wrong
# date, so a build without these arguments claims nothing.
ARG VCS_REF="unknown"
ARG BUILD_DATE="unknown"
LABEL org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}"
