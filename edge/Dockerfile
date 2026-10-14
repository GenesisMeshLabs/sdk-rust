# genesis-mesh-edge (beta): the image is built from the released, signed
# static binaries (edge.yml), never from source. HTTPS uses the agent's
# bundled web PKI roots, so the image holds no CA certificates.
FROM scratch
ARG TARGETARCH
ARG VERSION
COPY genesis-mesh-edge-${TARGETARCH} /genesis-mesh-edge
# The state and runtime directories belong to the agent's user, so a new
# volume starts out as the agent needs it (the context's empty/ directory).
COPY --chown=65532:65532 --chmod=0700 empty/ /var/lib/genesis-mesh-edge/
COPY --chown=65532:65532 --chmod=0750 empty/ /run/genesis-mesh-edge/
LABEL org.opencontainers.image.title="genesis-mesh-edge" \
      org.opencontainers.image.description="Genesis Mesh edge agent (beta)" \
      org.opencontainers.image.source="https://github.com/GenesisMeshLabs/sdk-rust" \
      org.opencontainers.image.documentation="https://github.com/GenesisMeshLabs/sdk-rust/blob/main/docs/edge.md" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"
ENV GM_EDGE_STATE_DIR=/var/lib/genesis-mesh-edge
USER 65532:65532
VOLUME ["/var/lib/genesis-mesh-edge", "/run/genesis-mesh-edge"]
ENTRYPOINT ["/genesis-mesh-edge"]
CMD ["run"]
