/* UI handles remain unpredictable on HTTP LAN pages where randomUUID is absent. */
function newUiSessionId() {
  if (typeof crypto.randomUUID === 'function') return 'demo-' + crypto.randomUUID();
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return 'demo-' + Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}
