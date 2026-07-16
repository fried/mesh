# mesh

Private E2E mailboxes. Server never sees plaintext.

`mesh-crypto` is the client — Signal-grade E2E (X3DH + Double Ratchet), 128MB files, forward secrecy, post-compromise security.

The server is a dumb mailbox — it only stores opaque `0x03` blobs. Self-host or bring your own.

## Build

```bash
cargo build --release
./target/release/mesh-crypto --help
```

## Usage

```bash
# 1. Generate identity (separate ed + x keys, 0600)
mesh-crypto gen
# -> ~/.mesh-v3/fp (64 hex), secret.key (32B ed_seed + 32B x_id_priv)

# 2. Claim mailbox
mesh-crypto claim --host https://your-server
# -> token saved to ~/.mesh-v3/keys/<FP>.key

# 3. Publish X3DH bundle
mesh-crypto x3dh publish --host https://your-server

# 4. Allow a peer (closed-by-default — empty = deny all except self)
mesh-crypto allow --fp <PEER_FP> --action allow --host https://your-server

# 5. Send
echo '{"hello":"world"}' | mesh-crypto send --to <PEER_FP> --host https://your-server
mesh-crypto send-file --to <PEER_FP> --file ./large.bin --host https://your-server

# 6. Poll (auto-decrypt, streaming, 64KiB RAM)
mesh-crypto poll --host https://your-server
```

## How it works

- **Identity**: ed25519 signing key (FP = hex(ed_pub)), x25519 identity key signed by ed. Separate keys, no reuse.
- **X3DH**: `DH(IK_A,SPK_B) || DH(EK_A,IK_B) || DH(EK_A,SPK_B) || DH(EK_A,OPK_B)` → HKDF info `fp_a||fp_b||spk_id||opk_id`
- **Double Ratchet**: per-message keys, header encryption, skipped keys LRU, N>10000 reject, 7-day timeout
- **Files**: STREAM (64KiB chunks, blake2b-256 hash, FK zeroize, truncation check)
- **Server**: Rust + axum, streaming O_TMPFILE+fsync+rename, quota 1GB / large≤3, rate 10MB/min, access_log off
- **Auth**: single token (32B base64url), O(1) HashMap, constant-time compare. Token loss = mailbox loss.

Wire: `0x03 || kem=x25519 || aead=xchacha20poly1305 || eph(32) || header || body/stream`

Server never sees plaintext — only opaque 0x03 blobs.

## Security

- E2EE, FS (ephemeral X3DH + ratchet, delete MK/CK), PCS (DH ratchet on reply)
- Deniability (no ed_sign in messages, MAC via MK only — both can forge)
- Replay / out-of-order via N/PN + header encryption + nonce uniqueness
- 128MB plaintext max (132MB wire = 2048*16 tags + header). Constant 64KiB RAM.

## License

MIT
