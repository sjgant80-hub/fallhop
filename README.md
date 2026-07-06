# FallHop

**Bitchat wire-format ⇄ Konomi translator.** Estate messages ride Jack Dorsey's Bluetooth-LE mesh; Bitchat packets arrive as estate-native (did:key + 7-ring) messages.

Live: https://sjgant80-hub.github.io/fallhop/

## What it is

Bitchat is a specific protocol Jack Dorsey shipped in July 2025 (repo: [permissionlesstech/bitchat](https://github.com/permissionlesstech/bitchat)). It moves signed, TTL-limited messages across a Bluetooth-LE mesh with no server. It has real install base and real reach.

FallHop is **not a Bitchat clone**. It is a **translator**:

- On the wire, it speaks Bitchat's binary v1/v2 format so estate users can appear as ordinary Bitchat peers on Bitchat's mesh.
- Inside the estate, it presents each Bitchat packet as a Konomi message: `did:key` identity, 7-ring hop model with κ = 0.618 attenuation per crossing, F(S⃗) fold-fingerprint over the payload, CID-anchored store-and-forward.

Bitchat becomes a lossy legacy protocol we translate to and from. The estate is a superset.

## What actually works in v1

Parsed and verified against the public source (BitFoundation package):

| Piece | v1 |
|---|---|
| Wire header (v1 14-byte, v2 16-byte) parse + emit | works |
| All 9 message types (announce, message, leave, courierEnvelope, noiseHandshake, noiseEncrypted, fragment, requestSync, fileTransfer) recognised | works |
| Flags (hasRecipient, hasSignature, isCompressed, hasRoute, isRSR) round-trip | works |
| TTL + hop model translated to Konomi 7 rings | works |
| Announce TLV body (nickname, noisePublicKey, signingPublicKey, directNeighbors) | works |
| Private-message TLV body (messageID + content) | works |
| Web Bluetooth transport wired to Bitchat's service UUID | wired, hardware-dependent |
| FallBridge transport (HTTP passthrough to a BLE dongle) | wired |
| FallCarrier registration | works |
| Duplicate-suppression + TTL-relay | works |

Honest limits:

- **Noise XX handshake** is preserved verbatim as opaque bytes — we do not derive session keys in v1. Full interop requires a Noise implementation (Curve25519 / ChaCha20-Poly1305 / SHA-256). Anything you can decrypt on native Bitchat is unchanged; anything encrypted is round-tripped as ciphertext.
- **Ed25519 signatures** are preserved but not verified in v1. Bitchat signs with TTL zeroed for relay compatibility (documented in `BitchatPacket.toBinaryDataForSigning`).
- **zlib compression** on payloads is a flagged Bitchat-only feature. We surface the flag under `bitchat_only.isCompressed`; the browser can decompress via `DecompressionStream` if you need to.
- **Fragmentation** (type 0x20) is parsed at the header level but not reassembled in v1.

If you rely on this in production, track the [`permissionlesstech/bitchat`](https://github.com/permissionlesstech/bitchat) protocol changes.

## API

```js
import {
  FallHop, WebBluetoothTransport, FallBridgeTransport,
  serialize, deserialize, bitchatToKonomi, konomiToBitchat, BITCHAT
} from './fallhop.js';

const hop = new FallHop({ fallid: { did: 'did:key:z6Mk…' }, transport: 'webbluetooth' });
hop.attachTransport(new WebBluetoothTransport());
hop.onMessage(({ raw, packet, konomi }) => console.log(konomi));
await hop.startListening();

await hop.send('did:key:z6MkTargetPeer…', 'hello mesh');
```

### The two translations

```js
// Bitchat wire bytes → estate-native
const pkt = deserialize(rawBytes);
const msg = bitchatToKonomi(pkt);
// msg.fromDid, msg.toDid, msg.ring, msg.ringHops, msg.hopsUsed,
// msg.kappa, msg.stateVector[7], msg.foldNumber, msg.body,
// msg.bitchat_only  ← loss report (fields with no clean Konomi analog)

// estate-native → Bitchat wire bytes
const bytes = konomiToBitchat(msg, { ttl: 7 });
```

### Konomi mappings

- **Identity.** Bitchat 8-byte peer ID → `did:bitchat:<hex>` wrapper. A full `did:key:z6Mk…` sender collapses to an 8-byte digest for the wire; the original DID is carried in application metadata.
- **Routing.** TTL 7 → 0 corresponds to spine crossings ● 〜 ┃ ♡ △ ◐ ◯. Each hop multiplies signal by κ = 0.618.
- **Payload.** Every payload gets a 7-slot state vector S⃗ (deterministic rolling hash mod 7) and a 16-bit fold number F(S⃗) as a message-metadata fingerprint.
- **Store-and-forward.** Undelivered Konomi messages are pinned by CID and replayed when a path opens (queue is transport-side; FallHop supplies the wire codec).

### Wire format supported

```
Header (v1: 14 B / v2: 16 B):
  [0]    version      (1 B)  1 or 2
  [1]    type         (1 B)  0x01..0x22
  [2]    ttl          (1 B)  0..7
  [3..10] timestamp   (8 B)  ms since epoch, big-endian
  [11]   flags        (1 B)  bit0 hasRecipient, bit1 hasSignature,
                             bit2 isCompressed, bit3 hasRoute, bit4 isRSR
  [12..] payloadLength (2 B v1 / 4 B v2)
Then: senderID (8), [recipientID (8)], [1 + n*8 route], payload (N), [signature (64)]
BLE service UUID (mainnet): F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C
BLE characteristic:         A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D
```

Reverse-engineered from public source (`BitFoundation/BinaryProtocol.swift`, `MessageType.swift`, `Packets.swift`, `BLEService.swift`). Bitchat itself is released under Unlicense (public domain); FallHop is MIT.

## Why interop, not walled garden

The estate rides Bitchat's install base. Bitchat users get estate services (Konomi rings, fold-fingerprints, did:key persistent identity, CID store-and-forward) without installing anything new. Estate users get Bitchat's real mesh reach without waiting for Simon's mesh to bootstrap. **Interop = network effect.**

## License

MIT (see [LICENSE](./LICENSE)). Bitchat itself is public-domain (Unlicense) at [permissionlesstech/bitchat](https://github.com/permissionlesstech/bitchat).

## Estate

Simon Gant · [AI-Native Solutions](https://ai-nativesolutions.com) · part of the FallSeed estate alongside [FallID](https://sjgant80-hub.github.io/fallid/), [FallCarrier](https://sjgant80-hub.github.io/fallcarrier/), [FallBridge](https://sjgant80-hub.github.io/fallbridge/), [FallMirror](https://sjgant80-hub.github.io/fallmirror/), [FallColony](https://sjgant80-hub.github.io/fallcolony/).
