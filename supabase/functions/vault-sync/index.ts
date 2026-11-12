/** 只接收加密快照，通过独立设备令牌鉴权，不记录凭据或请求正文。 */
const apiUrl = Deno.env.get('SUPABASE_URL')!;
const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const limit = 4 * 1024 * 1024;
const headers = { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' };
const reply = (status: number, value: unknown) => new Response(JSON.stringify(value), { status, headers });
async function digest(value: string): Promise<string> {
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, '0')).join('');
}
async function database(path: string, init: RequestInit = {}): Promise<Response> {
  return fetch(`${apiUrl}/rest/v1/${path}`, {
    ...init, headers: { apikey: serviceKey, Authorization: `Bearer ${serviceKey}`, 'Content-Type': 'application/json', ...init.headers },
  });
}
Deno.serve(async request => {
  if (request.method !== 'POST') return reply(405, { error: 'post_required' });
  const auth = request.headers.get('authorization') || '';
  if (!/^Bearer [A-Za-z0-9_-]{40,100}$/.test(auth)) return reply(401, { error: 'unauthorized' });
  const tokenHash = await digest(auth.slice(7));
  try {
    const found = await database(`vault_sync_devices?token_hash=eq.${tokenHash}&revoked=eq.false&select=device_id`);
    if (!found.ok) return reply(503, { error: 'authentication_store_unavailable' });
    const devices = await found.json();
    if (!Array.isArray(devices) || devices.length !== 1) return reply(401, { error: 'unauthorized' });
    if (Number(request.headers.get('content-length') || 0) > limit) return reply(413, { error: 'request_too_large' });
    const reader = request.body?.getReader();
    if (!reader) return reply(400, { error: 'json_required' });
    const chunks: Uint8Array[] = [];
    let size = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) { await reader.cancel(); return reply(413, { error: 'request_too_large' }); }
      chunks.push(value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    let body;
    try { body = JSON.parse(new TextDecoder().decode(bytes)); }
    catch { return reply(400, { error: 'invalid_json' }); }
    if (body.action === 'read') {
      const result = await database('vault_sync_snapshots?select=version,payload,entry_count,ciphertext_sha256,created_at&order=version.desc&limit=1');
      if (!result.ok) return reply(503, { error: 'snapshot_store_unavailable' });
      const rows = await result.json();
      return reply(200, { snapshot: rows[0] || null });
    }
    if (body.action === 'append') {
      const p = body.payload;
      if (!Number.isSafeInteger(body.expected_version) || body.expected_version < 0 ||
          !Number.isInteger(body.entry_count) || body.entry_count < 0 || body.entry_count > 10000 ||
          !p || p.version !== 1 || typeof p.nonce !== 'string' || !/^[A-Za-z0-9+/]{16}$/.test(p.nonce) ||
          typeof p.ciphertext !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(p.ciphertext) || p.ciphertext.length < 24 ||
          Object.keys(p).sort().join(',') !== 'ciphertext,nonce,version') {
        return reply(400, { error: 'invalid_encrypted_snapshot' });
      }
      const result = await database('rpc/vault_sync_append', { method: 'POST', body: JSON.stringify({
        p_expected_version: body.expected_version, p_payload: p, p_entry_count: body.entry_count,
        p_ciphertext_sha256: await digest(p.ciphertext), p_device_id: devices[0].device_id,
      }) });
      if (!result.ok) {
        const error = await result.json();
        return reply(error.code === 'PT409' ? 409 : 503, { error: error.code === 'PT409' ? 'snapshot_version_conflict' : 'snapshot_write_failed' });
      }
      return reply(200, { version: await result.json() });
    }
    if (body.action === 'enroll') {
      if (typeof body.device_id !== 'string' || !/^[A-Za-z0-9_-]{1,80}$/.test(body.device_id) ||
          typeof body.token_hash !== 'string' || !/^[0-9a-f]{64}$/.test(body.token_hash)) {
        return reply(400, { error: 'invalid_device' });
      }
      const result = await database('vault_sync_devices', { method: 'POST', body: JSON.stringify({ device_id: body.device_id, token_hash: body.token_hash }) });
      if (!result.ok) return reply(result.status === 409 ? 409 : 503, { error: 'device_enrollment_failed' });
      return reply(200, { enrolled: true });
    }
    return reply(400, { error: 'unknown_action' });
  } catch {
    return reply(503, { error: 'service_unavailable' });
  }
});
