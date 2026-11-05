'use strict';
// Encrypted GitHub Pages loader for Galaxy (built by deploy/pages/build.js).
// game.bin = 'GXE1' | iterations (u32 BE) | salt (16) | iv (12) | AES-256-GCM(ciphertext + tag).
// Key = PBKDF2-SHA256(access code, salt, iterations). Plaintext = u32 BE header length | header JSON | file bytes.
// The code can come from the form, from "remember on this device" (localStorage) or from an invite link "#k=CODE"
// (the part after # is never sent to the web server; it is removed from the address bar right away).
(() => {
  const KEY = 'galaxy-access-code';
  const $ = id => document.getElementById(id);
  const norm = c => String(c || '').trim().toLowerCase();
  let binPromise = null;
  const getBin = () => (binPromise = binPromise || fetch('game.bin', { cache: 'no-cache' }).then(r => {
    if (!r.ok) throw new Error('download failed (' + r.status + ')');
    return r.arrayBuffer();
  }));

  async function decrypt(code) {
    const buf = new Uint8Array(await getBin());
    if (String.fromCharCode(...buf.slice(0, 4)) !== 'GXE1') throw new Error('bad file');
    const iterations = new DataView(buf.buffer).getUint32(4);
    const salt = buf.slice(8, 24), iv = buf.slice(24, 36), ct = buf.slice(36);
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(norm(code)), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    try { return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct)); }
    catch (_) { const e = new Error('Wrong code.'); e.wrong = true; throw e; }
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
    for (const e of head.files) if (e.type.startsWith('image/')) GALAXY_ASSETS[e.path] = URL.createObjectURL(new Blob([file(e)], { type: e.type }));
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
      await mount(plain);
      return true;
    } catch (e) {
      if (e.wrong) { try { localStorage.removeItem(KEY); } catch (_) { /* ignore */ } }
      msg.textContent = e.wrong ? 'Wrong code.' : 'Could not load the game: ' + e.message;
      btn.disabled = false; btn.textContent = 'Enter';
      return false;
    }
  }

  $('gate-form').addEventListener('submit', ev => { ev.preventDefault(); tryCode($('gate-code').value, $('gate-remember').checked); });

  // invite link (#k=CODE) first, then a remembered code
  const m = /(?:^#|&)k=([^&]+)/.exec(location.hash);
  if (m) {
    history.replaceState(null, '', location.pathname + location.search);
    tryCode(decodeURIComponent(m[1]), true);
  } else {
    let saved = null; try { saved = localStorage.getItem(KEY); } catch (_) { /* ignore */ }
    if (saved) tryCode(saved, true);
  }
})();
