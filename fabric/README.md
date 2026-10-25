# SIH26237 Fabric integration update

## Environment variables (WSL Ubuntu paths)

Set these in the environment where the Windows Python backend is started:

```powershell
$env:FABRIC_NETWORK_DIR="/mnt/c/fabric/fabric-samples/test-network"
$env:FABRIC_CFG_PATH="/mnt/c/fabric/fabric-samples/config"
$env:FABRIC_BIN_DIR="/home/<your-wsl-user>/fabric-bin/bin"
$env:FABRIC_WSL_DISTRO="Ubuntu"
$env:FABRIC_CHANNEL="mychannel"
$env:FABRIC_CHAINCODE="provenance"
```

`FABRIC_BIN_DIR` must point to the directory containing `peer`. Paths are Linux/WSL paths, not Windows paths. The network folder must contain `scripts/envVar.sh`, `organizations/`, and the Fabric test-network files.

## Start network and deploy

In WSL Ubuntu:

```bash
cd /mnt/c/fabric/fabric-samples/test-network
export PATH="$HOME/fabric-bin/bin:$PATH"
export FABRIC_CFG_PATH=/mnt/c/fabric/fabric-samples/config
./network.sh up createChannel -c mychannel -ca
```

Copy the updated `chaincode.go` and its matching `go.mod`/`go.sum` into the chaincode project directory (do not mix it with a different contract dependency version). Then package and deploy using the same test-network flow used for the current installation. For Fabric samples v2.5, typical commands are:

```bash
./network.sh deployCC -c mychannel -ccn provenance -ccp /mnt/c/fabric/fabric-samples/decryption-provenance/chaincode -ccl go
```

If `provenance` is already deployed, the deploy command may require a version/sequence upgrade rather than a first deployment. Inspect the currently committed definition first; use the next sequence number and approve/commit for both Org1 and Org2 as required by the existing policy. Do not blindly rerun a first-deploy command against an existing chaincode.

## Python smoke test

Use a 64-character hexadecimal document hash and a unique watermark ID of 8-128 allowed characters:

```python
from fabric_client import FabricClient

client = FabricClient()
watermark = "demoWM_20261017"
doc_hash = "a" * 64
signature = "A" * 4400  # size smoke test only; NOT a real ML-DSA signature
proof = '{"proof":"demo"}'
timestamp = "2026-10-17T10:00:00.123456Z"

print(client.record_decryption(watermark, doc_hash, timestamp, signature, proof))
print(client.query_by_watermark(watermark))
print(client.verify(watermark, doc_hash, timestamp, signature, proof))
print(client.query_by_watermark("missingWM_20261017"))  # should return None
```

The sample signature is only a 4,400-character payload-size test, not a cryptographically valid signature. Use a fresh watermark for each successful write; duplicate watermark IDs should be rejected by chaincode.

## Important limitations

- The client sends commands through WSL's Fabric CLI, not the Fabric Gateway SDK or a REST/gRPC gateway.
- `verify()` checks that the ledger fields match the supplied local fields. It does not validate the ML-DSA signature or cryptographically verify the ZKP.
- The timeout is 60 seconds. Network-down conditions raise a readable `RuntimeError`.
- The configured network remains on the laptop/WSL installation where the Fabric containers and identities exist. This package does not include those containers, private identities, Docker volumes, or the WSL distribution, so it cannot independently tell the team which laptop will host the demo. The demo host must be explicitly agreed by the team.
- Before using this version, confirm the deployed chaincode schema matches the client payload keys (`watermarkID`, `documentHash`, `timestamp`, `dilithiumSig`, `zkpProof`).
