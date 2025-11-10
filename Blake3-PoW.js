'use strict';

class Blake3 {
  static IV = [
    0xbb67ae856a09e667n, 0xa54ff53a3c6ef372n,
    0x9b05688c510e527fn, 0x5be0cd191f83d9abn,
  ];

  static digestLongs(block) {
    const input = new Array(8).fill(0n);
    const copyLen = Math.min(block.length, 8);
    for (let i = 0; i < copyLen; i++) {
      input[i] = BigInt(block[i]) & MASK_64;
    }
    return Blake3.#hashInternal(input);
  }

  static digest(data) {
    const bytes = data instanceof Uint8Array ? data : Uint8Array.from(data);
    const input = new Array(8).fill(0n);
    const len = Math.min(bytes.length, 64);
    let off = 0;
    for (let i = 0; i < 8 && off < len; i++) {
      let w = 0n;
      for (let b = 0; b < 8 && off < len; b++, off++) {
        w |= BigInt(bytes[off] & 0xff) << (8n * BigInt(b));
      }
      input[i] = w & MASK_64;
    }

    const out = Blake3.#hashInternal(input);
    const digest = new Uint8Array(64);
    let pos = 0;
    for (let i = 0; i < out.length; i++) {
      const w = out[i];
      for (let b = 0; b < 8; b++) {
        digest[pos++] = Number((w >> (8n * BigInt(b))) & 0xffn);
      }
    }
    return digest;
  }

  static digest32(data) {
    const bytes = data instanceof Uint8Array ? data : Uint8Array.from(data);
    const input = new Array(8).fill(0n);
    const len = Math.min(bytes.length, 64);
    let off = 0;
    for (let i = 0; i < 8 && off < len; i++) {
      let w = 0n;
      for (let b = 0; b < 8 && off < len; b++, off++) {
        w |= BigInt(bytes[off] & 0xff) << (8n * BigInt(b));
      }
      input[i] = w & MASK_64;
    }

    const state = Blake3.#hashInternal(input);
    const mixed = [
      state[0] ^ state[4],
      state[1] ^ state[5],
      state[2] ^ state[6],
      state[3] ^ state[7],
    ];
    const out = new Uint8Array(32);
    let pos = 0;
    for (let i = 0; i < mixed.length; i++) {
      const w = mixed[i];
      for (let b = 0; b < 8; b++) {
        out[pos++] = Number((w >> (8n * BigInt(b))) & 0xffn);
      }
    }
    return out;
  }

  static hash(message, output) {
    const d = Blake3.digestLongs(message);
    const copyLen = Math.min(output.length, d.length);
    for (let i = 0; i < copyLen; i++) {
      output[i] = d[i];
    }
  }

  static #hashInternal(block) {
    const state = new Array(8).fill(0n);
    state[0] = Blake3.IV[0];
    state[1] = Blake3.IV[1];
    state[2] = Blake3.IV[2];
    state[3] = Blake3.IV[3];

    const padded = new Array(8).fill(0n);
    for (let i = 0; i < 8; i++) {
      padded[i] = (i < block.length ? block[i] : 0n) & MASK_64;
    }

    Blake3.#processBlock(padded, state);
    return state;
  }

  static #processBlock(inputWords, state) {
    const v = new Array(16).fill(0n);

    for (let i = 0; i < 4; i++) v[i] = state[i];
    for (let i = 0; i < 4; i++) v[4 + i] = Blake3.IV[i];
    for (let i = 0; i < 8; i++) v[8 + i] = inputWords[i] & MASK_64;
    const m = inputWords.slice();

    for (let round = 0; round < 5; round++) {
      Blake3.#G(v, 0, 4, 8, 12, m[0], m[1]);
      Blake3.#G(v, 1, 5, 9, 13, m[2], m[3]);
      Blake3.#G(v, 2, 6, 10, 14, m[4], m[5]);
      Blake3.#G(v, 3, 7, 11, 15, m[6], m[7]);
      Blake3.#G(v, 0, 5, 10, 15, m[1], m[2]);
      Blake3.#G(v, 1, 6, 11, 12, m[3], m[4]);
      Blake3.#G(v, 2, 7, 8, 13, m[5], m[6]);
      Blake3.#G(v, 3, 4, 9, 14, m[7], m[0]);

      if (round < 4) {
        const temp = m[0];
        for (let i = 0; i < 7; i++) m[i] = m[i + 1];
        m[7] = temp;
      }
    }

    for (let i = 0; i < 4; i++) {
      state[i] = (v[i] ^ v[i + 8]) & MASK_64;
    }
    for (let i = 4; i < 8; i++) {
      state[i] = (v[i] ^ v[i + 4]) & MASK_64;
    }
  }

  static #G(v, a, b, c, d, mx, my) {
    v[a] = add64(add64(v[a], v[b]), mx);
    v[d] = rotr64(v[d] ^ v[a], 32);
    v[c] = add64(v[c], v[d]);
    v[b] = rotr64(v[b] ^ v[c], 24);
    v[a] = add64(add64(v[a], v[b]), my);
    v[d] = rotr64(v[d] ^ v[a], 16);
    v[c] = add64(v[c], v[d]);
    v[b] = rotr64(v[b] ^ v[c], 63);
  }

  static leadingZeroBitsFromHex(hex) {
    let bits = 0;
    const s = hex.toLowerCase();
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i);
      let nibble;
      if (c >= 48 && c <= 57) { nibble = c - 48; } else { nibble = 10 + (c - 97); }
      if (nibble === 0) { bits += 4; continue; }
      if (nibble < 2) { bits += 3; }
      else if (nibble < 4) { bits += 2; }
      else if (nibble < 8) { bits += 1; }
      break;
    }
    return bits;
  }

  static minePowRange(start, end, secret, difficulty, reportEvery = 1000, progressCb = null) {
    let processed = 0;
    let lastHex = '';
    for (let nonce = start; nonce <= end; nonce++) {
      const hex = Blake3.hashHexString32(nonce.toString() + secret);
      lastHex = hex;
      const leading = Blake3.leadingZeroBitsFromHex(hex);
      if (leading >= difficulty) {
        return { nonce, hex };
      }
      processed++;
      if (progressCb && processed % reportEvery === 0) {
        progressCb({ done: reportEvery, lastHex });
      }
    }
    const remainder = processed % reportEvery;
    if (progressCb && remainder > 0) {
      progressCb({ done: remainder, lastHex });
    }
    return null;
  }

  static computeMaxNonce(diff) {
    const base = 100000;
    const bump = Math.max(0, diff - 8);
    return Math.min(5000000, base + bump * 250000);
  }

  static computeChunkSize(diff) {
    return diff >= 20 ? 2000 : 1000;
  }

  static hashHexString32(str) {
    const enc = new TextEncoder();
    const hash = Blake3.digest32(enc.encode(str));
    return [...hash].map(b => b.toString(16).padStart(2, '0')).join('');
  }

  static startPowChallenge({challengeSecret, difficulty}) {
    const ui = {
      status: document.getElementById('status'),
      progress: document.getElementById('progress'),
      dbgDifficulty: document.getElementById('dbg-difficulty'),
      dbgRange: document.getElementById('dbg-range'),
      dbgHash: document.getElementById('dbg-hash'),
      dbgHashCurrent: document.getElementById('dbg-hash-current'),
      dbgSalt: document.getElementById('dbg-salt'),
    };
    let solvedNonce = null;
    let startTime = Date.now();
    let progressPercent = 0;
    let lastHexCandidate = '';
    
    if (!ui.status) {
      console.warn('UI elements not found, creating minimal fallback UI');
      ui.status = { textContent: (text) => console.log('Status:', text) };
      ui.progress = { style: { width: '0%' } };
      ui.dbgDifficulty = { textContent: (text) => {} };
      ui.dbgRange = { textContent: (text) => {} };
      ui.dbgHash = { textContent: (text) => {} };
      ui.dbgHashCurrent = { textContent: (text) => {} };
      ui.dbgSalt = { textContent: (text) => {} };
    }
    
    ui.dbgDifficulty.textContent = String(difficulty);
    ui.dbgSalt.textContent = challengeSecret;
    ui.status.textContent = 'Loading crypto library...';
    try {
      ui.status.textContent = 'Mining...';
      const maxNonce = Blake3.computeMaxNonce(difficulty);
      const reportEvery = Blake3.computeChunkSize(difficulty);
      ui.dbgRange.textContent = `(0,${maxNonce.toLocaleString()})`;
      let totalProcessed = 0;
      let miningStopped = false;
      function progressCb({ done, lastHex }) {
        totalProcessed += done || 0;
        lastHexCandidate = lastHex || lastHexCandidate;
        const pct = Math.floor((totalProcessed / (maxNonce + 1)) * 100);
        progressPercent = Math.max(progressPercent, pct);
        ui.progress.style.width = `${progressPercent}%`;
        if (!solvedNonce && lastHexCandidate && ui.dbgHashCurrent) {
          ui.dbgHashCurrent.textContent = lastHexCandidate;
        }
      }
      const result = Blake3.minePowRange(0, maxNonce, challengeSecret, difficulty, reportEvery, progressCb);
      if (result) {
        solvedNonce = String(result.nonce);
        const hex = result.hex;
        const hashTime = (Date.now() - startTime) / 1000;
        if (ui.status) ui.status.textContent = `Found solution in ${hashTime}s! Verifying...`;
        if (ui.progress && ui.progress.style) ui.progress.style.width = '100%';
        if (ui.dbgHash) ui.dbgHash.textContent = hex;
        if (ui.dbgHashCurrent) ui.dbgHashCurrent.textContent = hex;
        miningStopped = true;
        verifyChallenge(solvedNonce);
      } else {
        if (ui.status) ui.status.textContent = 'No solution found within range. Refresh to try again.';
      }
      async function verifyChallenge(nonce) {
        try {
          console.log('Sending verification request with nonce:', nonce);
          const response = await fetch('/pow/validate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              nonce: nonce,
              challenge_secret: challengeSecret
            })
          });
          console.log('Response status:', response.status, 'OK:', response.ok);
          const result = await response.json();
          console.log('Verification result:', result);
          
          if (response.ok && result.verified) {
            if (ui.status) ui.status.textContent = 'Verification successful! Challenge completed.';
            setTimeout(() => {
              if (window.history.length > 1) {
                window.history.back();
              } else {
                window.location.href = '/';
              }
            }, 2000);
          } else {
            console.error('Verification failed:', result);
            if (ui.status) ui.status.textContent = 'Verification failed. Please try again.';
            setTimeout(() => location.reload(), 3000);
          }
        } catch (error) {
          console.error('Verification error:', error);
          if (ui.status) ui.status.textContent = 'An error occurred. Please try again.';
          setTimeout(() => location.reload(), 3000);
        }
      }
    } catch (err) {
      console.error('Failed to load Blake3.js:', err);
      if (ui.status) ui.status.textContent = 'Failed to load crypto library. Please refresh.';
    }
  }
}

const MASK_64 = (1n << 64n) - 1n;

function add64(a, b) {
  return (a + b) & MASK_64;
}

function rotr64(x, k) {
  const kk = BigInt(k) & 63n;
  // ((x >>> k) | (x << (64 - k))) & MASK_64
  return (((x >> kk) | ((x << (64n - kk)) & MASK_64)) & MASK_64);
}

if (typeof module !== 'undefined' && typeof module.exports !== 'undefined') {
  module.exports = Blake3;
} else if (typeof window !== 'undefined') {
  window.Blake3 = Blake3;
}

Blake3.toHex = function toHex(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) {
    s += bytes[i].toString(16).padStart(2, '0');
  }
  return s;
};

Blake3.hashHexString32 = function hashHexString32(str) {
  const enc = new TextEncoder();
  return Blake3.toHex(Blake3.digest32(enc.encode(str)));
};
