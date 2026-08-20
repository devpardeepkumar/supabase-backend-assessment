import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.49.1'

const TIMESTAMP_TOLERANCE_SECONDS = 300

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}

function hexToBytes(hex: string): Uint8Array | null {
  const clean = hex.trim().toLowerCase().replace(/^sha256=/, '')
  if (!/^[0-9a-f]+$/.test(clean) || clean.length % 2 !== 0) return null
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < clean.length; i += 2) {
    out[i / 2] = parseInt(clean.slice(i, i + 2), 16)
  }
  return out
}

async function hmacSha256(secret: string, payload: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload))
  return new Uint8Array(sig)
}

Deno.serve(async (req) => {
  if (req.method !== 'POST') {
    return json(405, { error: 'method_not_allowed' })
  }

  const secret = Deno.env.get('WEBHOOK_SECRET')
  if (!secret) {
    return json(500, { error: 'webhook_secret_not_configured' })
  }

  const rawBody = await req.text()
  const signatureHeader = req.headers.get('x-nexus-signature') ?? ''
  const timestampHeader = req.headers.get('x-nexus-timestamp') ?? ''
  const eventId = req.headers.get('x-nexus-event-id') ?? ''
  const eventType = req.headers.get('x-nexus-event-type') ?? 'unknown'

  const provided = hexToBytes(signatureHeader)
  if (!provided) {
    return json(401, { error: 'invalid_signature' })
  }

  const expected = await hmacSha256(secret, `${timestampHeader}.${rawBody}`)
  if (!timingSafeEqual(provided, expected)) {
    return json(401, { error: 'invalid_signature' })
  }

  const ts = Number(timestampHeader)
  if (!Number.isFinite(ts)) {
    return json(401, { error: 'invalid_timestamp' })
  }
  const now = Math.floor(Date.now() / 1000)
  if (Math.abs(now - ts) > TIMESTAMP_TOLERANCE_SECONDS) {
    return json(401, { error: 'replay_rejected' })
  }

  if (!eventId) {
    return json(400, { error: 'missing_event_id' })
  }

  let parsed: unknown = null
  try {
    parsed = rawBody ? JSON.parse(rawBody) : {}
  } catch {
    return json(400, { error: 'invalid_json' })
  }

  const supabaseUrl = Deno.env.get('SUPABASE_URL') ?? 'http://127.0.0.1:54321'
  const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')
  if (!serviceKey) {
    return json(500, { error: 'server_misconfigured' })
  }

  const admin = createClient(supabaseUrl, serviceKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  })

  const { data: inserted, error } = await admin.rpc('record_webhook_event', {
    _provider: 'external',
    _event_id: eventId,
    _event_type: eventType,
    _payload: parsed,
  })

  if (error) {
    return json(500, { error: 'processing_failed' })
  }

  if (inserted === false) {
    return json(200, { status: 'duplicate', event_id: eventId })
  }

  return json(200, { status: 'processed', event_id: eventId })
})
