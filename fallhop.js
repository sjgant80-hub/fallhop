/*!
 * FallHop v1 · Bitchat ↔ Konomi wire translator
 * AI-Native Solutions · MIT
 *
 * Not a Bitchat clone. A TRANSLATOR: parse/emit Bitchat's v1/v2 binary wire format
 * and map it to/from an estate-native (Konomi) representation. Bitchat becomes
 * a lossy legacy protocol we speak fluently; the estate face is did:key + rings.
 *
 * Verified against permissionlesstech/bitchat (BitFoundation package,
 * BinaryProtocol.swift + MessageType.swift + Packets.swift). Public domain source.
 *
 *   Header (v1: 14 bytes, v2: 16 bytes)
 *     [0]   version : 1
 *     [1]   type    : 1
 *     [2]   ttl     : 1
 *     [3..10] timestamp : 8  (ms since epoch, big-endian)
 *     [11]  flags   : 1  (bit0 hasRecipient, bit1 hasSignature,
 *                         bit2 isCompressed, bit3 hasRoute, bit4 isRSR)
 *     [12..] payloadLength : 2 (v1) or 4 (v2)
 *   Then:
 *     senderID (8), [recipientID (8)]?, [route (1 + 8*n)]?,
 *     [origSize (2 or 4) if compressed]?, payload (N),
 *     [signature (64)]?
 *
 *   BLE service UUID (mainnet): F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C
 *   BLE characteristic UUID   : A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D
 *
 *   MessageType: announce=0x01, message=0x02, leave=0x03,
 *                courierEnvelope=0x04, noiseHandshake=0x10, noiseEncrypted=0x11,
 *                fragment=0x20, requestSync=0x21, fileTransfer=0x22
 */

export const BITCHAT = Object.freeze({
  SERVICE_UUID_MAIN: 'f47b5e2d-4a9e-4c5a-9b3f-8e1d2c3a4b5c',
  SERVICE_UUID_TEST: 'f47b5e2d-4a9e-4c5a-9b3f-8e1d2c3a4b5a',
  CHAR_UUID:         'a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d',
  V1_HEADER: 14,
  V2_HEADER: 16,
  SENDER_ID: 8,
  RECIPIENT_ID: 8,
  SIG_SIZE: 64,
  MTU: 512,
  MAX_TTL: 7,
  TYPES: {
    0x01: 'announce', 0x02: 'message', 0x03: 'leave',
    0x04: 'courierEnvelope', 0x10: 'noiseHandshake', 0x11: 'noiseEncrypted',
    0x20: 'fragment', 0x21: 'requestSync', 0x22: 'fileTransfer'
  },
  FLAGS: { hasRecipient: 0x01, hasSignature: 0x02, isCompressed: 0x04, hasRoute: 0x08, isRSR: 0x10 }
});

// Konomi 7-ring hop model — each Bitchat hop is a ring crossing on the spine.
// κ = 0.618 signal per crossing. Max 7 hops = full spine traversal.
export const KONOMI_RINGS = ['●','〜','┃','♡','△','◐','◯'];
export const KAPPA = 0.618;

const te = new TextEncoder(), td = new TextDecoder();
const hex = b => Array.from(b, x => x.toString(16).padStart(2,'0')).join('');
const unhex = s => new Uint8Array((s.match(/../g)||[]).map(x=>parseInt(x,16)));
const nowMs = () => BigInt(Date.now());

// ---------- Bitchat wire codec ----------

export function serialize(packet) {
  const v = packet.version ?? 1;
  if (v !== 1 && v !== 2) throw new Error('bad version');
  const lenBytes = v === 2 ? 4 : 2;
  const headerSize = v === 2 ? 16 : 14;
  const payload = packet.payload || new Uint8Array(0);
  const sender = normId(packet.senderID);
  const hasRecipient = !!packet.recipientID;
  const recipient = hasRecipient ? normId(packet.recipientID) : null;
  const hasSig = !!packet.signature;
  const hasRoute = v >= 2 && Array.isArray(packet.route) && packet.route.length > 0;
  const routeBytes = hasRoute ? 1 + packet.route.length * 8 : 0;

  const totalLen = headerSize + 8 + (hasRecipient?8:0) + routeBytes + payload.length + (hasSig?64:0);
  const buf = new Uint8Array(totalLen);
  const dv = new DataView(buf.buffer);
  let o = 0;
  buf[o++] = v;
  buf[o++] = packet.type;
  buf[o++] = packet.ttl & 0xff;
  const ts = BigInt(packet.timestamp ?? nowMs());
  dv.setBigUint64(o, ts, false); o += 8;
  let flags = 0;
  if (hasRecipient) flags |= BITCHAT.FLAGS.hasRecipient;
  if (hasSig)       flags |= BITCHAT.FLAGS.hasSignature;
  if (hasRoute)     flags |= BITCHAT.FLAGS.hasRoute;
  if (packet.isRSR) flags |= BITCHAT.FLAGS.isRSR;
  buf[o++] = flags;
  if (lenBytes === 2) { dv.setUint16(o, payload.length, false); o += 2; }
  else                { dv.setUint32(o, payload.length, false); o += 4; }
  buf.set(sender, o); o += 8;
  if (hasRecipient) { buf.set(recipient, o); o += 8; }
  if (hasRoute) {
    buf[o++] = packet.route.length;
    for (const hop of packet.route) { buf.set(normId(hop), o); o += 8; }
  }
  buf.set(payload, o); o += payload.length;
  if (hasSig) { buf.set(new Uint8Array(packet.signature).subarray(0,64), o); o += 64; }
  return buf.subarray(0, o);
}

export function deserialize(bytes) {
  try {
    if (!bytes || bytes.length < 14 + 8) return null;
    const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    const version = b[0];
    if (version !== 1 && version !== 2) return null;
    const headerSize = version === 2 ? 16 : 14;
    const lenBytes  = version === 2 ? 4 : 2;
    if (b.length < headerSize + 8) return null;

    const type = b[1];
    if (!BITCHAT.TYPES[type]) return null;
    const ttl = b[2];
    const timestamp = dv.getBigUint64(3, false);
    const flags = b[11];
    const payloadLength = lenBytes === 2 ? dv.getUint16(12, false) : dv.getUint32(12, false);

    let o = headerSize;
    const senderID = b.slice(o, o + 8); o += 8;
    let recipientID = null;
    if (flags & BITCHAT.FLAGS.hasRecipient) {
      if (o + 8 > b.length) return null;
      recipientID = b.slice(o, o + 8); o += 8;
    }
    let route = null;
    if (flags & BITCHAT.FLAGS.hasRoute) {
      if (o + 1 > b.length) return null;
      const hops = b[o++];
      if (o + hops * 8 > b.length) return null;
      route = [];
      for (let i = 0; i < hops; i++) { route.push(b.slice(o, o + 8)); o += 8; }
    }
    if (o + payloadLength > b.length) return null;
    const payload = b.slice(o, o + payloadLength); o += payloadLength;
    let signature = null;
    if (flags & BITCHAT.FLAGS.hasSignature) {
      if (o + 64 > b.length) return null;
      signature = b.slice(o, o + 64); o += 64;
    }
    return {
      version, type, ttl, timestamp, flags,
      typeName: BITCHAT.TYPES[type],
      senderID, recipientID, route,
      isCompressed: !!(flags & BITCHAT.FLAGS.isCompressed),
      isRSR:        !!(flags & BITCHAT.FLAGS.isRSR),
      payload, signature
    };
  } catch { return null; }
}

// ---------- TLV bodies (announce, private message) ----------

export function encodeAnnouncement({ nickname, noisePublicKey, signingPublicKey }) {
  const n = te.encode(nickname); if (n.length > 255) throw new Error('nickname too long');
  const parts = [
    Uint8Array.of(0x01, n.length), n,
    Uint8Array.of(0x02, noisePublicKey.length), noisePublicKey,
    Uint8Array.of(0x03, signingPublicKey.length), signingPublicKey
  ];
  return concat(parts);
}
export function decodeAnnouncement(bytes) {
  const out = {}; let o = 0;
  while (o + 2 <= bytes.length) {
    const t = bytes[o++], L = bytes[o++]; if (o + L > bytes.length) break;
    const v = bytes.slice(o, o + L); o += L;
    if (t === 0x01) out.nickname = td.decode(v);
    else if (t === 0x02) out.noisePublicKey = v;
    else if (t === 0x03) out.signingPublicKey = v;
    else if (t === 0x04) out.directNeighbors = v;
  }
  return out.nickname ? out : null;
}
export function encodePublicMessage(text) { return te.encode(text); }
export function decodePublicMessage(bytes) { try { return td.decode(bytes); } catch { return null; } }
export function encodePrivateMessage({ messageID, content }) {
  const id = te.encode(messageID), c = te.encode(content);
  if (id.length > 255 || c.length > 255) throw new Error('field too long');
  return concat([Uint8Array.of(0x00, id.length), id, Uint8Array.of(0x01, c.length), c]);
}
export function decodePrivateMessage(bytes) {
  const out = {}; let o = 0;
  while (o + 2 <= bytes.length) {
    const t = bytes[o++], L = bytes[o++]; if (o + L > bytes.length) return null;
    const v = bytes.slice(o, o + L); o += L;
    if (t === 0x00) out.messageID = td.decode(v);
    else if (t === 0x01) out.content = td.decode(v);
  }
  return (out.messageID && out.content) ? out : null;
}

// ---------- Konomi translation ----------
// Bitchat model:  short peer IDs, TTL 0..7, timestamped payload.
// Konomi model:   did:key persistent identity, 7 rings on the spine, κ-attenuation,
//                 F(S⃗) 7-slot state-vector fingerprint, CID-anchored store-and-forward.

function ringsForTtl(ttl, startTtl = BITCHAT.MAX_TTL) {
  // Each hop crossed = one ring. hopsUsed = startTtl - ttl.
  const used = Math.max(0, Math.min(7, startTtl - ttl));
  return {
    hopsUsed: used,
    ringsCrossed: KONOMI_RINGS.slice(0, used),
    ringCurrent: KONOMI_RINGS[Math.min(6, used)],
    kappaRemaining: Math.pow(KAPPA, used)
  };
}

// F(S⃗) fingerprint over 7 slots derived from payload bytes. Deterministic, no crypto.
function foldFingerprint(bytes) {
  const S = new Uint16Array(7);
  for (let i = 0; i < bytes.length; i++) S[i % 7] = (S[i % 7] * 131 + bytes[i]) & 0xffff;
  const fold = Array.from(S, v => v.toString(16).padStart(4,'0')).join('-');
  const total = S.reduce((a,b)=>a+b, 0);
  return { S: Array.from(S), fold, foldNumber: total & 0xffff };
}

function peerIdToDid(peerId8) {
  // did:key form — 8-byte Bitchat peer ID is short, so we tag it as legacy.
  // A real full did:key ed25519 is 32-byte pubkey; we mark this as did:bitchat.
  return 'did:bitchat:' + hex(peerId8);
}
function didToPeerId(did) {
  if (did.startsWith('did:bitchat:')) return unhex(did.slice('did:bitchat:'.length));
  if (did.startsWith('did:key:')) {
    // Hash first 8 bytes of the identifier as a Bitchat-compatible short ID.
    const raw = te.encode(did);
    const out = new Uint8Array(8);
    for (let i = 0; i < raw.length; i++) out[i % 8] ^= raw[i];
    return out;
  }
  return new Uint8Array(8);
}

export function bitchatToKonomi(pkt) {
  if (!pkt) return null;
  const fromDid = peerIdToDid(pkt.senderID);
  const toDid   = pkt.recipientID ? peerIdToDid(pkt.recipientID) : null;
  const rings   = ringsForTtl(pkt.ttl);
  const fp      = foldFingerprint(pkt.payload);

  // Body decode by type.
  let konomiBody = null;
  if (pkt.typeName === 'announce') konomiBody = decodeAnnouncement(pkt.payload);
  else if (pkt.typeName === 'message') konomiBody = { text: decodePublicMessage(pkt.payload) };
  else if (pkt.typeName === 'noiseEncrypted') konomiBody = { opaque: 'noise-sealed', bytes: pkt.payload.length };
  else if (pkt.typeName === 'fragment') konomiBody = { opaque: 'fragment', bytes: pkt.payload.length };
  else konomiBody = { opaque: pkt.typeName, bytes: pkt.payload.length };

  // Loss report — fields Bitchat carries that estate does not natively model.
  const bitchatOnly = {
    version: pkt.version,          // wire-format version, no Konomi analog
    typeCode: pkt.type,
    ttlRaw: pkt.ttl,
    flagsRaw: pkt.flags,
    isRSR: pkt.isRSR,               // Reverse-Source-Routing flag — Bitchat-specific
    isCompressed: pkt.isCompressed, // zlib-on-wire, estate uses payload-agnostic CID
    signature: pkt.signature ? hex(pkt.signature) : null,
    route: pkt.route ? pkt.route.map(hex) : null,
    peerIDsHex: {
      sender: hex(pkt.senderID),
      recipient: pkt.recipientID ? hex(pkt.recipientID) : null
    }
  };

  return {
    kind: 'konomi.message',
    fromDid, toDid,
    ring: rings.ringCurrent,
    ringHops: rings.ringsCrossed,
    hopsUsed: rings.hopsUsed,
    kappa: rings.kappaRemaining,
    stateVector: fp.S,
    foldNumber: fp.foldNumber,
    foldFingerprint: fp.fold,
    timestamp: Number(pkt.timestamp),
    body: konomiBody,
    bitchat_only: bitchatOnly
  };
}

export function konomiToBitchat(msg, opts = {}) {
  const senderID = didToPeerId(msg.fromDid || 'did:bitchat:0000000000000000');
  const recipientID = msg.toDid ? didToPeerId(msg.toDid) : null;
  let type = 0x02, payload;
  if (msg.body && typeof msg.body.text === 'string') {
    type = 0x02; payload = encodePublicMessage(msg.body.text);
  } else if (msg.body && msg.body.nickname && msg.body.noisePublicKey && msg.body.signingPublicKey) {
    type = 0x01; payload = encodeAnnouncement(msg.body);
  } else if (msg.body && typeof msg.body.content === 'string' && msg.body.messageID) {
    type = 0x11; payload = encodePrivateMessage(msg.body); // wrap in noise on real deploy
  } else {
    type = 0x02; payload = te.encode(JSON.stringify(msg.body || {}));
  }
  const ttl = Math.max(0, Math.min(7, opts.ttl ?? (BITCHAT.MAX_TTL - (msg.hopsUsed || 0))));
  return serialize({
    version: opts.version || 1,
    type, ttl,
    senderID, recipientID,
    timestamp: msg.timestamp || Date.now(),
    payload
  });
}

// ---------- FallHop class — transport-agnostic driver ----------

export class FallHop {
  constructor({ fallid = null, transport = 'webbluetooth', maxTtl = 7 } = {}) {
    this.fallid = fallid;
    this.transportName = transport;
    this.maxTtl = maxTtl;
    this.seen = new Map();      // messageId hex -> lastSeen ms  (duplicate suppression)
    this.listeners = new Set();
    this.registered = false;
    this.transport = null;      // set by attachTransport
    this._registerHooks();
  }

  onMessage(fn) { this.listeners.add(fn); return () => this.listeners.delete(fn); }
  _emit(x) { for (const fn of this.listeners) { try { fn(x); } catch (e) { console.warn(e); } } }

  attachTransport(t) {
    this.transport = t;
    if (t && typeof t.onIncoming === 'function') {
      t.onIncoming(bytes => this.ingest(bytes));
    }
  }

  ingest(bytes) {
    const pkt = deserialize(bytes);
    if (!pkt) return null;
    const id = hex(pkt.senderID) + '-' + pkt.timestamp.toString(16);
    if (this.seen.has(id)) return null;
    this.seen.set(id, Date.now());
    if (this.seen.size > 2000) {
      const cutoff = Date.now() - 5 * 60 * 1000;
      for (const [k,v] of this.seen) if (v < cutoff) this.seen.delete(k);
    }
    const konomi = bitchatToKonomi(pkt);
    this._emit({ raw: bytes, packet: pkt, konomi });
    // Relay if TTL > 1 and we have a transport.
    if (pkt.ttl > 1 && this.transport && typeof this.transport.broadcast === 'function') {
      const relay = { ...pkt, ttl: pkt.ttl - 1 };
      try { this.transport.broadcast(serialize(relay)); } catch {}
    }
    return konomi;
  }

  async send(peerDid, message) {
    const bytes = konomiToBitchat({
      fromDid: this.fallid?.did || 'did:bitchat:0000000000000000',
      toDid: peerDid,
      body: typeof message === 'string' ? { text: message } : message
    }, { ttl: this.maxTtl });
    if (this.transport?.send) return this.transport.send(peerDid, bytes);
    if (this.transport?.broadcast) return this.transport.broadcast(bytes);
    return bytes; // no transport — return the wire bytes.
  }

  serialize(m)   { return serialize(m); }
  deserialize(b) { return deserialize(b); }

  async startListening() {
    if (this.transport?.start) return this.transport.start();
  }

  // FallCarrier registration — makes FallHop a routable transport in the estate.
  registerWithCarrier(carrier) {
    if (!carrier || typeof carrier.registerTransport !== 'function') return false;
    carrier.registerTransport('bitchat', {
      name: 'FallHop (Bitchat wire)',
      send: (peerDid, msg) => this.send(peerDid, msg),
      onMessage: (fn) => this.onMessage(fn),
      priority: 30
    });
    this.registered = true;
    return true;
  }

  _registerHooks() {
    if (typeof window !== 'undefined') {
      window.FallHop = window.FallHop || this;
    }
  }
}

// ---------- Web Bluetooth transport ----------

export class WebBluetoothTransport {
  constructor({ serviceUUID = BITCHAT.SERVICE_UUID_MAIN, charUUID = BITCHAT.CHAR_UUID } = {}) {
    this.serviceUUID = serviceUUID; this.charUUID = charUUID;
    this.device = null; this.characteristic = null;
    this._onIncoming = () => {};
    this.supported = typeof navigator !== 'undefined' && !!navigator.bluetooth;
  }
  onIncoming(fn) { this._onIncoming = fn; }
  async start() {
    if (!this.supported) throw new Error('Web Bluetooth not available');
    this.device = await navigator.bluetooth.requestDevice({
      filters: [{ services: [this.serviceUUID] }]
    });
    const server = await this.device.gatt.connect();
    const service = await server.getPrimaryService(this.serviceUUID);
    this.characteristic = await service.getCharacteristic(this.charUUID);
    await this.characteristic.startNotifications();
    this.characteristic.addEventListener('characteristicvaluechanged', ev => {
      const v = ev.target.value;
      const bytes = new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
      this._onIncoming(bytes);
    });
    return true;
  }
  async broadcast(bytes) {
    if (!this.characteristic) throw new Error('not connected');
    // BLE MTU = 512, fragment if larger. v1 spec: fragment type 0x20.
    const chunks = [];
    for (let i = 0; i < bytes.length; i += 500) chunks.push(bytes.slice(i, i + 500));
    for (const c of chunks) await this.characteristic.writeValueWithoutResponse(c);
    return true;
  }
  async send(_did, bytes) { return this.broadcast(bytes); }
}

// ---------- FallBridge transport (BLE dongle passthrough) ----------

export class FallBridgeTransport {
  constructor({ endpoint = 'http://localhost:8378/bridge', poll = 1500 } = {}) {
    this.endpoint = endpoint; this.poll = poll; this._onIncoming = () => {};
    this._timer = null;
  }
  onIncoming(fn) { this._onIncoming = fn; }
  async start() {
    this._timer = setInterval(async () => {
      try {
        const r = await fetch(this.endpoint + '/rx', { cache: 'no-store' });
        if (!r.ok) return;
        const arr = new Uint8Array(await r.arrayBuffer());
        if (arr.length) this._onIncoming(arr);
      } catch {}
    }, this.poll);
    return true;
  }
  async broadcast(bytes) {
    try {
      await fetch(this.endpoint + '/tx', {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream' },
        body: bytes
      });
    } catch {}
    return true;
  }
  async send(_did, bytes) { return this.broadcast(bytes); }
}

// ---------- Utilities ----------

function normId(x) {
  if (x instanceof Uint8Array) {
    if (x.length === 8) return x;
    if (x.length > 8)    return x.slice(0, 8);
    const out = new Uint8Array(8); out.set(x, 0); return out;
  }
  if (typeof x === 'string') {
    if (x.startsWith('did:')) return didToPeerId(x);
    if (/^[0-9a-f]+$/i.test(x)) {
      const raw = unhex(x);
      return normId(raw);
    }
    return normId(te.encode(x));
  }
  return new Uint8Array(8);
}
function concat(parts) {
  const total = parts.reduce((a,b)=>a+b.length,0);
  const out = new Uint8Array(total);
  let o = 0; for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export { hex, unhex, ringsForTtl, foldFingerprint, peerIdToDid, didToPeerId };
export default FallHop;
