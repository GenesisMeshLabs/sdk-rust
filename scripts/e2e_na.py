"""Disposable loopback NA for SDK integration tests. Requires the Python core installed.

Only generated test credentials are emitted, to the parent test process. The
real HTTP routes, signatures, policy enforcement and SQLite store are used.
"""
import inspect
import json
import signal
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from werkzeug.serving import make_server
from genesis_mesh.crypto import generate_keypair, sign_model
from genesis_mesh.models import GenesisBlock, NetworkAuthority, PolicyManifestRef
from genesis_mesh.na_service.server import NetworkAuthorityService


def main():
    root = generate_keypair()
    operator = generate_keypair()
    now = datetime.now(timezone.utc)
    genesis = GenesisBlock(
        network_name="sdk-e2e", network_version="v0.1", root_public_key=root.public_key_b64,
        network_authority=NetworkAuthority(public_key=root.public_key_b64, valid_from=now, valid_to=now + timedelta(days=1)),
        policy_manifest=PolicyManifestRef(hash="sha256:test", url=None),
    )
    genesis.signatures.append(sign_model(genesis, root.private_key, "root"))
    # Changes outside the controlled path, on a core that has them (1.3.0).
    options = {}
    if "evidence_out_of_band" in inspect.signature(NetworkAuthorityService.__init__).parameters:
        options["evidence_out_of_band"] = "on"
    with tempfile.TemporaryDirectory(prefix="gm-sdk-e2e-") as tmp:
        service = NetworkAuthorityService(
            genesis_block=genesis, na_private_key=root.private_key, key_id="na-e2e",
            db_path=str(Path(tmp) / "na.db"), operator_public_keys={"ops": operator.public_key_b64},
            operator_key_tiers={"ops": "privileged"}, boundary_policy_enforcement="required", evidence_store="on",
            **options,
        )
        # Do not spend a minute between pages in a local integration test.
        service.rate_limiter.allow = lambda *args, **kwargs: True
        server = make_server("127.0.0.1", 0, service.app)
        signal.signal(signal.SIGTERM, lambda *_: exit(0))
        print(json.dumps({"baseUrl": f"http://127.0.0.1:{server.server_port}",
                          "signingKeyBase64": operator.private_key_b64, "keyId": "ops",
                          "naPublicKey": root.public_key_b64, "outOfBand": bool(options)}), flush=True)
        try:
            server.serve_forever()
        finally:
            server.server_close()


if __name__ == "__main__":
    main()
