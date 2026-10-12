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
    reviewer = generate_keypair()
    now = datetime.now(timezone.utc)
    genesis = GenesisBlock(
        network_name="sdk-e2e", network_version="v0.1", root_public_key=root.public_key_b64,
        network_authority=NetworkAuthority(public_key=root.public_key_b64, valid_from=now, valid_to=now + timedelta(days=1)),
        policy_manifest=PolicyManifestRef(hash="sha256:test", url=None),
    )
    genesis.signatures.append(sign_model(genesis, root.private_key, "root"))
    # Changes outside the controlled path, on a core that has them (1.3.0).
    options = {}
    parameters = inspect.signature(NetworkAuthorityService.__init__).parameters
    if "evidence_out_of_band" in parameters:
        options["evidence_out_of_band"] = "on"
    # Remediation and reviews, on a core that has them (1.4.0): a second
    # privileged key of another named holder decides reviews.
    operator_keys = {"ops": operator.public_key_b64}
    tiers = {"ops": "privileged"}
    remediation = "evidence_remediation" in parameters
    if remediation:
        options["evidence_remediation"] = "on"
        options["operator_key_holders"] = {"ops": "alice", "reviewer": "bob"}
        operator_keys["reviewer"] = reviewer.public_key_b64
        tiers["reviewer"] = "privileged"
    with tempfile.TemporaryDirectory(prefix="gm-sdk-e2e-") as tmp:
        service = NetworkAuthorityService(
            genesis_block=genesis, na_private_key=root.private_key, key_id="na-e2e",
            db_path=str(Path(tmp) / "na.db"), operator_public_keys=operator_keys,
            operator_key_tiers=tiers, boundary_policy_enforcement="required", evidence_store="on",
            **options,
        )
        # Do not spend a minute between pages in a local integration test.
        service.rate_limiter.allow = lambda *args, **kwargs: True
        server = make_server("127.0.0.1", 0, service.app)
        signal.signal(signal.SIGTERM, lambda *_: exit(0))
        config = {"baseUrl": f"http://127.0.0.1:{server.server_port}",
                  "signingKeyBase64": operator.private_key_b64, "keyId": "ops",
                  "naPublicKey": root.public_key_b64, "outOfBand": "evidence_out_of_band" in options,
                  "remediation": remediation}
        if remediation:
            config.update({"reviewerKeyId": "reviewer", "reviewerSigningKeyBase64": reviewer.private_key_b64})
        print(json.dumps(config), flush=True)
        try:
            server.serve_forever()
        finally:
            server.server_close()


if __name__ == "__main__":
    main()
