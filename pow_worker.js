importScripts('https://cdn.jsdelivr.net/gh/libalpm64/Blake3-JS@refs/heads/main/Blake3-PoW.js');

self.onmessage = function(ev) {
  const { start, end, secret, difficulty, reportEvery } = ev.data;
  let processed = 0;
  let lastHex = '';
  for (let nonce = start; nonce <= end; nonce++) {
    const hex = Blake3.hashHexString32(nonce.toString() + secret);
    lastHex = hex;
    const leading = Blake3.leadingZeroBitsFromHex(hex);
    if (leading >= difficulty) {
      self.postMessage({ type: 'found', nonce, hex });
      return;
    }
    processed++;
    if (processed % reportEvery === 0) {
      self.postMessage({ type: 'progress', done: reportEvery, lastHex });
    }
  }
  const remainder = processed % reportEvery;
  if (remainder > 0) {
    self.postMessage({ type: 'progress', done: remainder, lastHex });
  }
  self.postMessage({ type: 'done' });
};