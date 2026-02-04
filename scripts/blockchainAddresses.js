/**
 * Blockchain Address Derivation Utilities
 * Derives addresses for multiple blockchains from a single FLO/BTC WIF private key
 *
 * Supported Blockchains:
 * - XRP (Ripple) - via xrpl library
 * - SUI - via nacl + BLAKE2b
 * - TON - via nacl + TonWeb
 * - TRON - via TronWeb
 * - DOGE - via bitjs with version byte 0x1e
 *
 * Dependencies :
 * - bitjs (for WIF decoding)
 * - Crypto.util (for hex/bytes conversion)
 * - xrpl (for XRP)
 * - nacl/TweetNaCl (for SUI, TON)
 * - TonWeb (for TON)
 * - TronWeb (for TRON)
 */

// BlakeJS - BLAKE2b hashing implementation for SUI
const blakejs = (function () {
  const BLAKE2B_IV32 = new Uint32Array([
    0xf3bcc908, 0x6a09e667, 0x84caa73b, 0xbb67ae85, 0xfe94f82b, 0x3c6ef372,
    0x5f1d36f1, 0xa54ff53a, 0xade682d1, 0x510e527f, 0x2b3e6c1f, 0x9b05688c,
    0xfb41bd6b, 0x1f83d9ab, 0x137e2179, 0x5be0cd19,
  ]);
  const SIGMA8 = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 14, 10, 4, 8, 9, 15,
    13, 6, 1, 12, 0, 2, 11, 7, 5, 3, 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6,
    7, 1, 9, 4, 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8, 9, 0, 5,
    7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13, 2, 12, 6, 10, 0, 11, 8, 3, 4,
    13, 7, 5, 15, 14, 1, 9, 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8,
    11, 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10, 6, 15, 14, 9, 11,
    3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5, 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14,
    3, 12, 13, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 14, 10,
    4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
  ];
  const SIGMA82 = new Uint8Array(SIGMA8.map((x) => x * 2));
  const v = new Uint32Array(32);
  const m = new Uint32Array(32);
  const parameterBlock = new Uint8Array(64);

  function B2B_GET32(arr, i) {
    return arr[i] ^ (arr[i + 1] << 8) ^ (arr[i + 2] << 16) ^ (arr[i + 3] << 24);
  }
  function ADD64AA(v, a, b) {
    const o0 = v[a] + v[b];
    let o1 = v[a + 1] + v[b + 1];
    if (o0 >= 0x100000000) o1++;
    v[a] = o0;
    v[a + 1] = o1;
  }
  function ADD64AC(v, a, b0, b1) {
    let o0 = v[a] + b0;
    if (b0 < 0) o0 += 0x100000000;
    let o1 = v[a + 1] + b1;
    if (o0 >= 0x100000000) o1++;
    v[a] = o0;
    v[a + 1] = o1;
  }
  function B2B_G(a, b, c, d, ix, iy) {
    const x0 = m[ix],
      x1 = m[ix + 1],
      y0 = m[iy],
      y1 = m[iy + 1];
    ADD64AA(v, a, b);
    ADD64AC(v, a, x0, x1);
    let xor0 = v[d] ^ v[a],
      xor1 = v[d + 1] ^ v[a + 1];
    v[d] = xor1;
    v[d + 1] = xor0;
    ADD64AA(v, c, d);
    xor0 = v[b] ^ v[c];
    xor1 = v[b + 1] ^ v[c + 1];
    v[b] = (xor0 >>> 24) ^ (xor1 << 8);
    v[b + 1] = (xor1 >>> 24) ^ (xor0 << 8);
    ADD64AA(v, a, b);
    ADD64AC(v, a, y0, y1);
    xor0 = v[d] ^ v[a];
    xor1 = v[d + 1] ^ v[a + 1];
    v[d] = (xor0 >>> 16) ^ (xor1 << 16);
    v[d + 1] = (xor1 >>> 16) ^ (xor0 << 16);
    ADD64AA(v, c, d);
    xor0 = v[b] ^ v[c];
    xor1 = v[b + 1] ^ v[c + 1];
    v[b] = (xor1 >>> 31) ^ (xor0 << 1);
    v[b + 1] = (xor0 >>> 31) ^ (xor1 << 1);
  }
  function blake2bCompress(ctx, last) {
    let i;
    for (i = 0; i < 16; i++) {
      v[i] = ctx.h[i];
      v[i + 16] = BLAKE2B_IV32[i];
    }
    v[24] = v[24] ^ ctx.t;
    v[25] = v[25] ^ (ctx.t / 0x100000000);
    if (last) {
      v[28] = ~v[28];
      v[29] = ~v[29];
    }
    for (i = 0; i < 32; i++) m[i] = B2B_GET32(ctx.b, 4 * i);
    for (i = 0; i < 12; i++) {
      B2B_G(0, 8, 16, 24, SIGMA82[i * 16 + 0], SIGMA82[i * 16 + 1]);
      B2B_G(2, 10, 18, 26, SIGMA82[i * 16 + 2], SIGMA82[i * 16 + 3]);
      B2B_G(4, 12, 20, 28, SIGMA82[i * 16 + 4], SIGMA82[i * 16 + 5]);
      B2B_G(6, 14, 22, 30, SIGMA82[i * 16 + 6], SIGMA82[i * 16 + 7]);
      B2B_G(0, 10, 20, 30, SIGMA82[i * 16 + 8], SIGMA82[i * 16 + 9]);
      B2B_G(2, 12, 22, 24, SIGMA82[i * 16 + 10], SIGMA82[i * 16 + 11]);
      B2B_G(4, 14, 16, 26, SIGMA82[i * 16 + 12], SIGMA82[i * 16 + 13]);
      B2B_G(6, 8, 18, 28, SIGMA82[i * 16 + 14], SIGMA82[i * 16 + 15]);
    }
    for (i = 0; i < 16; i++) ctx.h[i] = ctx.h[i] ^ v[i] ^ v[i + 16];
  }
  function blake2bInit(outlen, key) {
    const ctx = {
      b: new Uint8Array(128),
      h: new Uint32Array(16),
      t: 0,
      c: 0,
      outlen: outlen,
    };
    parameterBlock.fill(0);
    parameterBlock[0] = outlen;
    if (key) parameterBlock[1] = key.length;
    parameterBlock[2] = 1;
    parameterBlock[3] = 1;
    for (let i = 0; i < 16; i++)
      ctx.h[i] = BLAKE2B_IV32[i] ^ B2B_GET32(parameterBlock, i * 4);
    if (key) {
      blake2bUpdate(ctx, key);
      ctx.c = 128;
    }
    return ctx;
  }
  function blake2bUpdate(ctx, input) {
    for (let i = 0; i < input.length; i++) {
      if (ctx.c === 128) {
        ctx.t += ctx.c;
        blake2bCompress(ctx, false);
        ctx.c = 0;
      }
      ctx.b[ctx.c++] = input[i];
    }
  }
  function blake2bFinal(ctx) {
    ctx.t += ctx.c;
    while (ctx.c < 128) ctx.b[ctx.c++] = 0;
    blake2bCompress(ctx, true);
    const out = new Uint8Array(ctx.outlen);
    for (let i = 0; i < ctx.outlen; i++)
      out[i] = ctx.h[i >> 2] >> (8 * (i & 3));
    return out;
  }
  function blake2b(input, key, outlen) {
    outlen = outlen || 64;
    if (!(input instanceof Uint8Array)) {
      if (typeof input === "string") {
        const enc = unescape(encodeURIComponent(input));
        input = new Uint8Array(enc.length);
        for (let i = 0; i < enc.length; i++) input[i] = enc.charCodeAt(i);
      } else throw new Error("Input must be string or Uint8Array");
    }
    const ctx = blake2bInit(outlen, key);
    blake2bUpdate(ctx, input);
    return blake2bFinal(ctx);
  }
  return { blake2b: blake2b };
})();

/**
 * Convert WIF private key to XRP (Ripple) address
 * Uses xrpl library with Ed25519 derivation
 * @param {string} wif - WIF format private key
 * @returns {string|null} XRP address or null on error
 */
function convertWIFtoXrpAddress(wif) {
  try {
    if (typeof window.xrpl === "undefined") {
      throw new Error("xrpl library not loaded");
    }
    if (typeof bitjs === "undefined") {
      throw new Error("bitjs library not loaded");
    }
    // Use bitjs.wif2privkey to decode WIF and get the raw private key hex
    const decoded = bitjs.wif2privkey(wif);
    if (!decoded || !decoded.privkey) {
      throw new Error("Failed to decode WIF private key");
    }
    // Convert hex string to byte array for xrpl
    const keyBytes = Crypto.util.hexToBytes(decoded.privkey);
    // Create XRP wallet from entropy (raw private key bytes)
    const wallet = xrpl.Wallet.fromEntropy(keyBytes);
    return wallet.address;
  } catch (error) {
    console.error("WIF to XRP conversion error:", error);
    return null;
  }
}

/**
 * Convert WIF private key to SUI address
 * Uses Ed25519 keypair + BLAKE2b-256 hashing
 * @param {string} wif - WIF format private key
 * @returns {string|null} SUI address (0x prefixed) or null on error
 */
function convertWIFtoSuiAddress(wif) {
  try {
    if (typeof nacl === "undefined") {
      throw new Error("nacl (TweetNaCl) library not loaded");
    }
    if (typeof bitjs === "undefined") {
      throw new Error("bitjs library not loaded");
    }
    // Use bitjs.wif2privkey to decode WIF and get the raw private key hex
    const decoded = bitjs.wif2privkey(wif);
    if (!decoded || !decoded.privkey) {
      throw new Error("Failed to decode WIF private key");
    }
    // Get first 32 bytes (64 hex chars) for Ed25519 seed
    const privKeyHex = decoded.privkey.substring(0, 64);
    const privBytes = Crypto.util.hexToBytes(privKeyHex);
    const seed = new Uint8Array(privBytes.slice(0, 32));
    // Generate Ed25519 keypair from seed
    const keyPair = nacl.sign.keyPair.fromSeed(seed);
    const pubKey = keyPair.publicKey;
    // Prefix public key with 0x00 (Ed25519 scheme flag)
    const prefixedPubKey = new Uint8Array([0x00, ...pubKey]);
    // Hash with BLAKE2b-256
    const hash = blakejs.blake2b(prefixedPubKey, null, 32);
    // Convert to hex address with 0x prefix
    const suiAddress = "0x" + Crypto.util.bytesToHex(hash);
    return suiAddress;
  } catch (error) {
    console.error("WIF to SUI conversion error:", error);
    return null;
  }
}

/**
 * Convert WIF private key to TON address
 * Uses Ed25519 keypair + TonWeb v4R2 wallet
 * @param {string} wif - WIF format private key
 * @returns {Promise<string|null>} TON address (bounceable format) or null on error
 */
async function convertWIFtoTonAddress(wif) {
  try {
    if (typeof nacl === "undefined") {
      throw new Error("nacl (TweetNaCl) library not loaded");
    }
    if (typeof TonWeb === "undefined") {
      throw new Error("TonWeb library not loaded");
    }
    if (typeof bitjs === "undefined") {
      throw new Error("bitjs library not loaded");
    }
    // Use bitjs.wif2privkey to decode WIF and get the raw private key hex
    const decoded = bitjs.wif2privkey(wif);
    if (!decoded || !decoded.privkey) {
      throw new Error("Failed to decode WIF private key");
    }
    // Get first 32 bytes (64 hex chars) for Ed25519 seed
    const privKeyHex = decoded.privkey.substring(0, 64);
    const seed = Crypto.util.hexToBytes(privKeyHex);
    // Generate Ed25519 keypair from seed
    const keyPair = nacl.sign.keyPair.fromSeed(new Uint8Array(seed));
    // Create TON wallet using TonWeb v4R2 wallet
    const tonweb = new TonWeb();
    const WalletClass = TonWeb.Wallets.all.v4R2;
    if (!WalletClass) {
      throw new Error("TonWeb v4R2 wallet not available");
    }
    const wallet = new WalletClass(tonweb.provider, {
      publicKey: keyPair.publicKey,
    });
    const address = await wallet.getAddress();
    // Return user-friendly bounceable address
    return address.toString(true, true, false);
  } catch (error) {
    console.error("WIF to TON conversion error:", error);
    return null;
  }
}

/**
 * Convert WIF private key to TRON address
 * Uses TronWeb library for address derivation
 * @param {string} wif - WIF format private key
 * @returns {string|null} TRON address (Base58 format) or null on error
 */
function convertWIFtoTronAddress(wif) {
  try {
    if (typeof TronWeb === "undefined") {
      throw new Error("TronWeb library not loaded");
    }
    if (typeof bitjs === "undefined") {
      throw new Error("bitjs library not loaded");
    }
    // Use bitjs.wif2privkey to decode WIF and get the raw private key hex
    const decoded = bitjs.wif2privkey(wif);
    if (!decoded || !decoded.privkey) {
      throw new Error("Failed to decode WIF private key");
    }
    // Get the hex private key (64 chars)
    const privKeyHex = decoded.privkey.substring(0, 64);
    // Use TronWeb to derive address from private key
    const tronAddress = TronWeb.address.fromPrivateKey(privKeyHex);
    return tronAddress;
  } catch (error) {
    console.error("WIF to TRON conversion error:", error);
    return null;
  }
}

/**
 * Derive all blockchain addresses from a WIF private key
 * @param {string} wif - WIF format private key
 * @returns {Promise<Object>} Object containing all derived addresses
 */
async function deriveAllBlockchainAddresses(wif) {
  const addresses = {
    xrp: null,
    sui: null,
    ton: null,
    tron: null,
    doge: null,
  };

  try {
    addresses.xrp = convertWIFtoXrpAddress(wif);
  } catch (e) {
    console.warn("XRP derivation failed:", e);
  }
  try {
    addresses.sui = convertWIFtoSuiAddress(wif);
  } catch (e) {
    console.warn("SUI derivation failed:", e);
  }
  try {
    addresses.ton = await convertWIFtoTonAddress(wif);
  } catch (e) {
    console.warn("TON derivation failed:", e);
  }
  try {
    addresses.tron = convertWIFtoTronAddress(wif);
  } catch (e) {
    console.warn("TRON derivation failed:", e);
  }
  try {
    addresses.doge = convertWIFtoDogeAddress(wif);
  } catch (e) {
    console.warn("DOGE derivation failed:", e);
  }

  return addresses;
}

/**
 * Convert WIF private key to DOGE (Dogecoin) address
 * Uses secp256k1 with version byte 0x1e (30)
 * @param {string} wif - WIF format private key
 * @returns {string|null} DOGE address (Base58 format starting with 'D') or null on error
 */
function convertWIFtoDogeAddress(wif) {
  try {
    // Store original settings
    const origPub = bitjs.pub;
    const origPriv = bitjs.priv;
    const origBitjsCompressed = bitjs.compressed;

    // Decode WIF to get raw private key and determine if compressed
    const decode = Bitcoin.Base58.decode(wif);
    const keyWithVersion = decode.slice(0, decode.length - 4);
    let key = keyWithVersion.slice(1);

    let compressed = true;
    if (key.length >= 33 && key[key.length - 1] === 0x01) {
      // Compressed WIF has 0x01 suffix
      key = key.slice(0, key.length - 1);
      compressed = true;
    } else {
      compressed = false;
    }

    const privKeyHex = Crypto.util.bytesToHex(key);

    // Set DOGE version bytes and compression
    bitjs.pub = 0x1e;
    bitjs.priv = 0x9e;
    bitjs.compressed = compressed;

    // Generate public key from private key
    const pubKey = bitjs.newPubkey(privKeyHex);
    // Generate DOGE address from public key
    const dogeAddress = bitjs.pubkey2address(pubKey);

    // Restore original settings
    bitjs.pub = origPub;
    bitjs.priv = origPriv;
    bitjs.compressed = origBitjsCompressed;

    return dogeAddress;
  } catch (error) {
    console.error("WIF to DOGE conversion error:", error);
    return null;
  }
}
