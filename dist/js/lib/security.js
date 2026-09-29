/* Escaping helpers — every interpolated value in an innerHTML template must
   pass through one of these. */

export function esc(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
    .replace(/`/g, '&#96;');
}

export function escAttr(s) {
  return String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}

/* Only allow http(s) URLs into href attributes. */
export function safeUrl(u) {
  try {
    const url = new URL(String(u), location.origin);
    return (url.protocol === 'http:' || url.protocol === 'https:') ? url.href : '#';
  } catch { return '#'; }
}

export function host(u) {
  try { return new URL(String(u), location.origin).hostname.replace(/^www\./, ''); } catch { return ''; }
}
