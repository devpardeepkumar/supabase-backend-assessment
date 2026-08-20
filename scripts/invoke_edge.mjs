/**
 * HTTP checks for invite-member, external-webhook, Storage MIME, Realtime auth.
 * Requires running API (supabase start) and `supabase functions serve`.
 *
 *   $env:SUPABASE_ANON_KEY="<anon from supabase status>"
 *   $env:SUPABASE_SERVICE_ROLE_KEY="<service_role from supabase status>"
 *   $env:WEBHOOK_SECRET="replace-with-a-long-random-secret"
 *   node scripts/invoke_edge.mjs
 */
import { createClient } from '@supabase/supabase-js'
import { createHmac } from 'node:crypto'

const url = process.env.SUPABASE_URL ?? 'http://127.0.0.1:54321'
const anon = process.env.SUPABASE_ANON_KEY
const service = process.env.SUPABASE_SERVICE_ROLE_KEY
const webhookSecret = process.env.WEBHOOK_SECRET ?? 'replace-with-a-long-random-secret'

if (!anon) {
  console.error('Set SUPABASE_ANON_KEY from `supabase status` (do not commit it).')
  process.exit(1)
}

let failed = 0
function expect(name, ok, detail = '') {
  if (ok) {
    console.log(`ok - ${name}`)
  } else {
    failed += 1
    console.log(`not ok - ${name}${detail ? `: ${detail}` : ''}`)
  }
}

async function signIn(email) {
  const res = await fetch(`${url}/auth/v1/token?grant_type=password`, {
    method: 'POST',
    headers: { apikey: anon, 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password: 'password' }),
  })
  const body = await res.json()
  if (!res.ok || !body.access_token) {
    throw new Error(`sign-in failed for ${email}: ${res.status}`)
  }
  return body.access_token
}

function sign(raw, timestamp) {
  return `sha256=${createHmac('sha256', webhookSecret).update(`${timestamp}.${raw}`).digest('hex')}`
}

async function jsonCall(path, { token, extraHeaders = {}, body, method = 'POST' }) {
  const res = await fetch(`${url}${path}`, {
    method,
    headers: {
      apikey: anon,
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      'Content-Type': 'application/json',
      ...extraHeaders,
    },
    body,
  })
  const text = await res.text()
  return { status: res.status, text }
}

async function main() {
  const ownerToken = await signIn('a-owner@example.com')
  const memberToken = await signIn('a-member@example.com')
  const contributorToken = await signIn('a-contributor@example.com')

  const anonInvite = await jsonCall('/functions/v1/invite-member', {
    body: JSON.stringify({
      organisation_id: 'a0000000-0000-0000-0000-0000000000a1',
      email: 'anon@example.com',
      role: 'member',
    }),
  })
  expect('invite-member anonymous denied', anonInvite.status === 401, String(anonInvite.status))

  const memberInvite = await jsonCall('/functions/v1/invite-member', {
    token: memberToken,
    body: JSON.stringify({
      organisation_id: 'a0000000-0000-0000-0000-0000000000a1',
      email: 'member-cannot-invite@example.com',
      role: 'member',
    }),
  })
  expect('invite-member member denied', memberInvite.status === 403 || memberInvite.status === 401, String(memberInvite.status))

  const ownerInvite = await jsonCall('/functions/v1/invite-member', {
    token: ownerToken,
    body: JSON.stringify({
      organisation_id: 'a0000000-0000-0000-0000-0000000000a1',
      email: 'edge-invitee@example.com',
      role: 'member',
    }),
  })
  expect('invite-member owner allowed', ownerInvite.status === 200, `${ownerInvite.status} ${ownerInvite.text}`)
  if (ownerInvite.status === 200) {
    const parsed = JSON.parse(ownerInvite.text)
    expect('invite-member does not return service role', !JSON.stringify(parsed).includes('service_role'))
    expect('invite-member returns dev invite_url', typeof parsed.invite_url === 'string')
  }

  const raw = '{"ok":true}'
  const ts = Math.floor(Date.now() / 1000).toString()
  const eventId = `evt_http_${Date.now()}`
  const webhookHeaders = {
    'x-nexus-timestamp': ts,
    'x-nexus-event-id': eventId,
    'x-nexus-event-type': 'ping',
  }

  const bad = await jsonCall('/functions/v1/external-webhook', {
    extraHeaders: { ...webhookHeaders, 'x-nexus-signature': 'sha256=00' },
    body: raw,
  })
  expect('webhook invalid signature rejected', bad.status === 401, String(bad.status))

  if (service) {
    const admin = createClient(url, service, { auth: { persistSession: false, autoRefreshToken: false } })
    const { count: before } = await admin.from('webhook_events').select('*', { count: 'exact', head: true }).eq('event_id', eventId)
    expect('invalid signature created no webhook row', (before ?? 0) === 0)
  }

  const first = await jsonCall('/functions/v1/external-webhook', {
    extraHeaders: { ...webhookHeaders, 'x-nexus-signature': sign(raw, ts) },
    body: raw,
  })
  expect('webhook valid signature processed', first.status === 200 && first.text.includes('processed'), `${first.status} ${first.text}`)

  const second = await jsonCall('/functions/v1/external-webhook', {
    extraHeaders: { ...webhookHeaders, 'x-nexus-signature': sign(raw, ts) },
    body: raw,
  })
  expect('webhook duplicate is idempotent', second.status === 200 && second.text.includes('duplicate'), `${second.status} ${second.text}`)

  const contrib = createClient(url, anon, {
    global: { headers: { Authorization: `Bearer ${contributorToken}` } },
    auth: { persistSession: false, autoRefreshToken: false },
  })
  const path = `a0000000-0000-0000-0000-0000000000a1/a0000000-0000-0000-0000-000000000101/mime-${Date.now()}.bin`
  const { error: mimeError } = await contrib.storage.from('project-files').upload(path, new Uint8Array([1, 2, 3]), {
    contentType: 'application/x-msdownload',
    upsert: false,
  })
  expect('storage rejects disallowed MIME type', Boolean(mimeError), mimeError ? mimeError.message : 'upload succeeded')

  const { error: okUpload } = await contrib.storage.from('project-files').upload(
    `a0000000-0000-0000-0000-0000000000a1/a0000000-0000-0000-0000-000000000101/ok-${Date.now()}.txt`,
    'hello',
    { contentType: 'text/plain', upsert: false },
  )
  expect('storage allows text/plain upload', !okUpload, okUpload ? okUpload.message : '')

  const foreign = contrib.channel(`project:b0000000-0000-0000-0000-000000000101`, { config: { private: true } })
  const subStatus = await new Promise((resolve) => {
    const timer = setTimeout(() => resolve('timeout'), 8000)
    foreign.subscribe((status) => {
      if (status === 'SUBSCRIBED' || status === 'CHANNEL_ERROR' || status === 'TIMED_OUT' || status === 'CLOSED') {
        clearTimeout(timer)
        resolve(status)
      }
    })
  })
  expect(
    'realtime deny guessed foreign project',
    subStatus !== 'SUBSCRIBED',
    String(subStatus),
  )
  await contrib.removeChannel(foreign)

  if (failed > 0) {
    console.error(`${failed} HTTP check(s) failed`)
    process.exit(1)
  }
  console.log('All HTTP checks passed.')
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
