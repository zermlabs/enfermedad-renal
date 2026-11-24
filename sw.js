// Descifra la exposición en el navegador. La portada (index.html) le manda la llave que sale de la contraseña;
// aquí se guarda en IndexedDB y cada archivo que pide la presentación se trae cifrado de c/<ruta>.bin y se descifra.
const BASE = new URL('./', self.registration.scope).pathname;
const PUBLICOS = new Set(['', 'index.html', 'sw.js', 'sal.json', 'robots.txt']);
const TIPOS = { html: 'text/html; charset=utf-8', js: 'text/javascript; charset=utf-8', json: 'application/json', mp4: 'video/mp4', webm: 'video/webm',
  webp: 'image/webp', jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', svg: 'image/svg+xml', woff2: 'font/woff2', css: 'text/css; charset=utf-8' };
let llave = null;
const medios = new Map();   // videos ya descifrados (el navegador los pide por partes)

const base = () => new Promise((ok, mal) => {
  const r = indexedDB.open('exposicion-renal', 1);
  r.onupgradeneeded = () => r.result.createObjectStore('llave');
  r.onsuccess = () => ok(r.result); r.onerror = () => mal(r.error);
});
async function guardar(bytes) {
  const d = await base();
  await new Promise((ok, mal) => { const t = d.transaction('llave', 'readwrite'); bytes ? t.objectStore('llave').put(bytes, 'k') : t.objectStore('llave').delete('k'); t.oncomplete = ok; t.onerror = () => mal(t.error); });
}
async function leer() {
  if (llave) return llave;
  const d = await base();
  const bytes = await new Promise(ok => { const r = d.transaction('llave').objectStore('llave').get('k'); r.onsuccess = () => ok(r.result || null); r.onerror = () => ok(null); });
  if (!bytes) return null;
  return llave = await crypto.subtle.importKey('raw', bytes, 'AES-GCM', false, ['decrypt']);
}

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('message', e => {
  const m = e.data || {}, responder = v => e.ports[0] && e.ports[0].postMessage(v);
  if (m.llave) e.waitUntil(crypto.subtle.importKey('raw', m.llave, 'AES-GCM', false, ['decrypt']).then(async k => { llave = k; medios.clear(); await guardar(m.llave); responder('ok'); }));
  else if (m.estado) e.waitUntil(leer().then(k => responder(!!k), () => responder(false)));
  else if (m.salir) e.waitUntil((async () => { llave = null; medios.clear(); await guardar(null); responder('ok'); })());
});

self.addEventListener('fetch', e => {
  const u = new URL(e.request.url);
  if (u.origin !== location.origin || !u.pathname.startsWith(BASE) || e.request.method !== 'GET') return;
  const ruta = decodeURIComponent(u.pathname.slice(BASE.length));
  if (PUBLICOS.has(ruta) || ruta.startsWith('c/') || ruta.startsWith('puerta/')) return;
  e.respondWith(servir(ruta, e.request));
});

async function servir(ruta, peticion) {
  const aEntrada = () => peticion.mode === 'navigate' ? Response.redirect(BASE, 302) : new Response('Falta la contraseña', { status: 401 });
  const k = await leer();
  if (!k) return aEntrada();
  let cuerpo = medios.get(ruta);
  if (!cuerpo) {
    const r = await fetch(BASE + 'c/' + ruta.split('/').map(encodeURIComponent).join('/') + '.bin');
    if (!r.ok) return new Response('No existe', { status: 404 });
    const b = await r.arrayBuffer();
    try { cuerpo = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(b, 0, 12) }, k, new Uint8Array(b, 12)); }
    catch (err) { llave = null; await guardar(null); return aEntrada(); }      // la contraseña cambió: se vuelve a pedir
    if (/\.(mp4|webm)$/.test(ruta)) { medios.set(ruta, cuerpo); if (medios.size > 6) medios.delete(medios.keys().next().value); }
  }
  const tipo = TIPOS[ruta.split('.').pop().toLowerCase()] || 'application/octet-stream', largo = cuerpo.byteLength;
  const rango = /bytes=(\d*)-(\d*)/.exec(peticion.headers.get('range') || '');
  if (rango) {
    let ini = rango[1] === '' ? Math.max(0, largo - +rango[2]) : +rango[1];
    let fin = rango[1] !== '' && rango[2] !== '' ? Math.min(+rango[2], largo - 1) : largo - 1;
    if (ini >= largo) return new Response(null, { status: 416, headers: { 'Content-Range': `bytes */${largo}` } });
    return new Response(cuerpo.slice(ini, fin + 1), { status: 206, headers: { 'Content-Type': tipo, 'Accept-Ranges': 'bytes',
      'Content-Range': `bytes ${ini}-${fin}/${largo}`, 'Content-Length': String(fin - ini + 1) } });
  }
  return new Response(cuerpo, { headers: { 'Content-Type': tipo, 'Accept-Ranges': 'bytes', 'Content-Length': String(largo) } });
}
