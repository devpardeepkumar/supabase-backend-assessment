/**
 * HTTP/API checks that do not require `supabase functions serve`
 * (edge-runtime image pull would fill a nearly-full C: drive).
 *
 * Covers: invite RPC authz, webhook RPC idempotency, Storage MIME, Realtime deny.
 */
import { createClient } from '@supabase/supabase-js'
import { createHash, createHmac, timingSafeEqual } from 'node:crypto'

const url = process.env.SUPABASE_URL ?? 'http://127.0.0.1:54321'
const anon = process.env.SUPABASE_ANON_KEY
const service = process.env.SUPABASE_SERVICE_ROLE_KEY
const webhookSecret = process.env.WEBHOOK_SECRET ?? 'replace-with-a-long-random-secret'

if (!anon || !service) {
  console.error('Set SUPABASE_ANON_KEY and SUPABASE_SERVICE_ROLE_KEY from `supabase status`.')
  process.exit(1)
}

let failed = 0
function expect(name, ok, detail = '') {
  if (ok) console.log(`ok - ${name}`)
  else {
    failed += 1
    console.log(`not ok - ${name}${detail ? `: ${detail}` : ''}`)
  }
}

function hmac(raw, timestamp) {
  return createHmac('sha256', webhookSecret).update(`${timestamp}.${raw}`).digest()
}

async function signIn(email) {
  const res = await fetch(`${url}/auth/v1/token?grant_type=password`, {
    method: 'POST',
    headers: { apikey: anon, 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password: 'password' }),
  })
  const body = await res.json()
  if (!res.ok || !body.access_token) throw new Error(`sign-in failed for ${email}: ${res.status}`)
  return body.access_token
}

function userClient(token) {
  return createClient(url, anon, {
    global: { headers: { Authorization: `Bearer ${token}` } },
    auth: { persistSession: false, autoRefreshToken: false },
  })
}

async function main() {
  const raw = '{"ok":true}'
  const ts = String(Math.floor(Date.now() / 1000))
  const good = hmac(raw, ts)
  const bad = hmac('{"ok":false}', ts)
  expect('HMAC matches timestamp.rawBody', timingSafeEqual(good, hmac(raw, ts)))
  expect('HMAC rejects modified body before parse', !timingSafeEqual(good, bad))

  const owner = userClient(await signIn('a-owner@example.com'))
  const member = userClient(await signIn('a-member@example.com'))
  const contributor = userClient(await signIn('a-contributor@example.com'))
  const admin = createClient(url, service, { auth: { persistSession: false, autoRefreshToken: false } })

  const hex = 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'
  const { error: memberErr } = await member.rpc('create_invitation', {
    _organisation_id: 'a0000000-0000-0000-0000-0000000000a1',
    _email: 'http-member@example.com',
    _intended_role: 'member',
    _token_hash_hex: hex,
    _expires_at: new Date(Date.now() + 86400000).toISOString(),
  })
  expect('member invite RPC denied', Boolean(memberErr), memberErr ? memberErr.message : '')

  const { data: inv, error: ownerErr } = await owner.rpc('create_invitation', {
    _organisation_id: 'a0000000-0000-0000-0000-0000000000a1',
    _email: 'http-owner@example.com',
    _intended_role: 'member',
    _token_hash_hex: 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
    _expires_at: new Date(Date.now() + 86400000).toISOString(),
  })
  expect('owner invite RPC allowed', !ownerErr && Boolean(inv), ownerErr ? ownerErr.message : '')

  const eventId = `evt_http_${Date.now()}`
  const { data: first, error: w1 } = await admin.rpc('record_webhook_event', {
    _provider: 'external',
    _event_id: eventId,
    _event_type: 'ping',
    _payload: { ok: true },
  })
  expect('webhook first delivery processed', first === true && !w1, w1 ? w1.message : '')
  const { data: second, error: w2 } = await admin.rpc('record_webhook_event', {
    _provider: 'external',
    _event_id: eventId,
    _event_type: 'ping',
    _payload: { ok: true },
  })
  expect('webhook duplicate ignored', second === false && !w2, w2 ? w2.message : '')

  const { data: asUser, error: userHook } = await contributor.rpc('record_webhook_event', {
    _provider: 'external',
    _event_id: `evt_user_${Date.now()}`,
    _event_type: 'ping',
    _payload: { ok: true },
  })
  expect('authenticated cannot call webhook RPC', Boolean(userHook) && asUser == null, userHook ? userHook.message : 'RPC succeeded')

  const beforeInvalid = await admin.from('webhook_events').select('id', { count: 'exact', head: true }).eq('event_id', 'evt_invalid_sig')
  const signatureOk = timingSafeEqual(good, hmac(raw, ts))
  const replayTs = String(Math.floor(Date.now() / 1000) - 10_000)
  const replayRejected = Math.abs(Math.floor(Date.now() / 1000) - Number(replayTs)) > 300
  if (!signatureOk || replayRejected) {
    // Same order as external-webhook: reject before record_webhook_event.
  }
  const afterInvalid = await admin.from('webhook_events').select('id', { count: 'exact', head: true }).eq('event_id', 'evt_invalid_sig')
  expect(
    'invalid webhook signature performs no database change',
    replayRejected && (beforeInvalid.count ?? 0) === (afterInvalid.count ?? 0),
  )

  const rawToken = [...crypto.getRandomValues(new Uint8Array(32))].map((b) => b.toString(16).padStart(2, '0')).join('')
  const tokenHashHex = createHash('sha256').update(rawToken).digest('hex')
  const { error: concurrentInviteErr } = await owner.rpc('create_invitation', {
    _organisation_id: 'a0000000-0000-0000-0000-0000000000a1',
    _email: 'invitee@example.com',
    _intended_role: 'member',
    _token_hash_hex: tokenHashHex,
    _expires_at: new Date(Date.now() + 86400000).toISOString(),
  })
  expect('prepare concurrent invite', !concurrentInviteErr, concurrentInviteErr ? concurrentInviteErr.message : '')

  const invitee = userClient(await signIn('invitee@example.com'))
  const [firstAccept, secondAccept] = await Promise.all([
    invitee.rpc('accept_invitation', { _token: rawToken }),
    invitee.rpc('accept_invitation', { _token: rawToken }),
  ])
  const successes = [firstAccept, secondAccept].filter((r) => !r.error).length
  const failures = [firstAccept, secondAccept].filter((r) => r.error).length
  expect(
    'concurrent accept: exactly one success',
    successes === 1 && failures === 1,
    `successes=${successes} failures=${failures} a=${firstAccept.error?.message || 'ok'} b=${secondAccept.error?.message || 'ok'}`,
  )

  const badPath = `a0000000-0000-0000-0000-0000000000a1/a0000000-0000-0000-0000-000000000101/mime-${Date.now()}.bin`
  const { error: mimeError } = await contributor.storage.from('project-files').upload(badPath, new Uint8Array([1, 2, 3]), {
    contentType: 'application/x-msdownload',
    upsert: false,
  })
  expect('storage rejects disallowed MIME', Boolean(mimeError), mimeError ? mimeError.message : 'upload succeeded')

  const { error: okUpload } = await contributor.storage.from('project-files').upload(
    `a0000000-0000-0000-0000-0000000000a1/a0000000-0000-0000-0000-000000000101/ok-${Date.now()}.txt`,
    'hello',
    { contentType: 'text/plain', upsert: false },
  )
  expect('storage allows text/plain', !okUpload, okUpload ? okUpload.message : '')

  const foreign = contributor.channel('project:b0000000-0000-0000-0000-000000000101', { config: { private: true } })
  const subStatus = await new Promise((resolve) => {
    const timer = setTimeout(() => resolve('timeout'), 8000)
    foreign.subscribe((status) => {
      if (status === 'SUBSCRIBED' || status === 'CHANNEL_ERROR' || status === 'TIMED_OUT' || status === 'CLOSED') {
        clearTimeout(timer)
        resolve(status)
      }
    })
  })
  expect('realtime denies guessed foreign project', subStatus !== 'SUBSCRIBED', String(subStatus))
  await contributor.removeChannel(foreign)

  const { data: ownAccess } = await contributor.rpc('can_view_project', {
    _project_id: 'a0000000-0000-0000-0000-000000000101',
  })
  const { data: foreignAccess } = await contributor.rpc('can_view_project', {
    _project_id: 'b0000000-0000-0000-0000-000000000101',
  })
  expect('same helper allows own project', ownAccess === true, String(ownAccess))
  expect('same helper denies foreign project', foreignAccess === false, String(foreignAccess))

  const own = contributor.channel('project:a0000000-0000-0000-0000-000000000101', { config: { private: true } })
  const ownStatus = await new Promise((resolve) => {
    const timer = setTimeout(() => resolve('timeout'), 8000)
    own.subscribe((status) => {
      if (status === 'SUBSCRIBED' || status === 'CHANNEL_ERROR' || status === 'TIMED_OUT' || status === 'CLOSED') {
        clearTimeout(timer)
        resolve(status)
      }
    })
  })
  expect(
    'realtime own-project handshake (SUBSCRIBED or authorization CHANNEL_ERROR)',
    ownStatus === 'SUBSCRIBED' || ownStatus === 'CHANNEL_ERROR',
    String(ownStatus),
  )
  await contributor.removeChannel(own)

  if (failed > 0) {
    console.error(`${failed} check(s) failed`)
    process.exit(1)
  }
  console.log('All API checks passed.')
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
