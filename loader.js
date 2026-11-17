'use strict';
// Encrypted GitHub Pages loader for Galaxy (built by deploy/pages/build.js).
// game.bin = 'GXE1' | iterations (u32 BE) | salt (16) | iv (12) | AES-256-GCM(ciphertext + tag).
// Key = PBKDF2-SHA256(access code, salt, iterations). Plaintext = u32 BE header length | header JSON | file bytes.
// The code can come from the form, from "remember on this device" (localStorage) or from an invite link "#k=CODE"
// (the part after # is never sent to the web server; the code is removed from the address bar right away,
// other parts such as a peer-to-peer room=… stay for the game).
(() => {
  const KEY = 'galaxy-access-code';
  const $ = id => document.getElementById(id);
  const norm = c => String(c || '').trim().toLowerCase();
  // Download progress for the "Unlocking…" button (the download starts as soon as the page opens).
  let got = 0, total = 0;
  const fetchBin = (name, onChunk) => fetch(name, { cache: 'no-cache' }).then(async r => {
    if (!r.ok) throw new Error('download failed (' + r.status + ')');
    if (!r.body || !onChunk) return new Uint8Array(await r.arrayBuffer());
    const size = +r.headers.get('content-length') || 0, parts = [], rd = r.body.getReader();
    for (let n = 0; ;) {
      const { done, value } = await rd.read(); if (done) break;
      parts.push(value); n += value.length; onChunk(n, size);
    }
    const out = new Uint8Array(parts.reduce((a, p) => a + p.length, 0)); let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  });
  let binPromise = null;
  const getBin = () => (binPromise = binPromise || fetchBin('game.bin', (n, size) => { got = n; total = size; progress(); }));
  const progress = () => {
    const btn = $('gate-go');
    if (btn && btn.disabled && total && got < total) btn.textContent = `Loading ${Math.round(got / total * 100)} %…`;
  };

  let keyCache = null;   // { code, salt, key }: the music file uses the same key, so it is derived only once
  async function open(buf, code) {
    if (String.fromCharCode(...buf.slice(0, 4)) !== 'GXE1') throw new Error('bad file');
    const iterations = new DataView(buf.buffer, buf.byteOffset).getUint32(4);
    const salt = buf.slice(8, 24), iv = buf.slice(24, 36), ct = buf.slice(36);
    if (!keyCache || keyCache.code !== norm(code) || keyCache.salt.join() !== salt.join()) {
      const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(norm(code)), 'PBKDF2', false, ['deriveKey']);
      keyCache = { code: norm(code), salt, key: await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']) };
    }
    try { return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, keyCache.key, ct)); }
    catch (_) { keyCache = null; const e = new Error('Wrong code.'); e.wrong = true; throw e; }
  }
  async function decrypt(code) {
    const buf = await getBin();
    const btn = $('gate-go'); if (btn && btn.disabled) btn.textContent = 'Unlocking…';
    return open(buf, code);
  }

  // Start-screen music: fetched once the game is on screen; the game picks it up from GALAXY_ASSETS.
  function loadMusic(code) {
    fetchBin('music.bin').then(buf => open(buf, code)).then(mp3 => {
      GALAXY_ASSETS['audio/menu.mp3'] = URL.createObjectURL(new Blob([mp3], { type: 'audio/mpeg' }));
      document.dispatchEvent(new Event('galaxy-music'));
    }).catch(() => { /* no music: the game still works */ });
  }

  function loadScript(src) {
    return new Promise((res, rej) => { const s = document.createElement('script'); s.src = src; s.onload = res; s.onerror = () => rej(new Error('script failed')); document.body.append(s); });
  }

  async function mount(plain) {
    const n = new DataView(plain.buffer, plain.byteOffset).getUint32(0);
    const head = JSON.parse(new TextDecoder().decode(plain.subarray(4, 4 + n)));
    const data = plain.subarray(4 + n);
    const file = e => data.subarray(e.off, e.off + e.len);
    window.GALAXY_ASSETS = {};
    for (const e of head.files) if (/^(image|audio)\//.test(e.type)) GALAXY_ASSETS[e.path] = URL.createObjectURL(new Blob([file(e)], { type: e.type }));
    for (const e of head.files) if (e.type === 'text/css') { const st = document.createElement('style'); st.textContent = new TextDecoder().decode(file(e)); document.head.append(st); }
    for (const p of head.scripts) {   // same order as the game's index.html
      const e = head.files.find(f => f.path === p);
      const url = URL.createObjectURL(new Blob([file(e)], { type: 'text/javascript' }));
      await loadScript(url);
      URL.revokeObjectURL(url);
    }
    $('gate').remove();
    document.title = head.title || 'Galaxy';
    document.dispatchEvent(new Event('DOMContentLoaded', { bubbles: true }));   // the game starts on DOMContentLoaded
  }

  async function tryCode(code, remember) {
    const msg = $('gate-msg'), btn = $('gate-go');
    msg.textContent = ''; btn.disabled = true; btn.textContent = 'Unlocking…';
    try {
      const plain = await decrypt(code);
      if (remember) { try { localStorage.setItem(KEY, norm(code)); } catch (_) { /* private mode */ } }
      window.GALAXY_CODE = norm(code);   // lets the game build peer-to-peer invite links that open in one click
      await mount(plain);
      loadMusic(code);
      return true;
    } catch (e) {
      if (e.wrong) { try { localStorage.removeItem(KEY); } catch (_) { /* ignore */ } }
      msg.textContent = e.wrong ? 'Wrong code.' : 'Could not load the game: ' + e.message;
      btn.disabled = false; btn.textContent = 'Enter';
      return false;
    }
  }

  getBin().catch(() => { binPromise = null; });   // start downloading while the player types the code

  $('gate-form').addEventListener('submit', ev => { ev.preventDefault(); tryCode($('gate-code').value, $('gate-remember').checked); });

  // invite link (#k=CODE) first, then a remembered code
  const m = /(?:^#|&)k=([^&]+)/.exec(location.hash);
  if (m) {
    const rest = location.hash.slice(1).split('&').filter(x => x && !x.startsWith('k=')).join('&');   // keep e.g. room=…
    history.replaceState(null, '', location.pathname + location.search + (rest ? '#' + rest : ''));
    tryCode(decodeURIComponent(m[1]), true);
  } else {
    let saved = null; try { saved = localStorage.getItem(KEY); } catch (_) { /* ignore */ }
    if (saved) tryCode(saved, true);
  }
})();
