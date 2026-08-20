import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.49.1'

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  })
}

function randomToken(): string {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('')
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  if (req.method !== 'POST') {
    return json(405, { error: 'method_not_allowed' })
  }

  const authHeader = req.headers.get('Authorization')
  if (!authHeader) {
    return json(401, { error: 'unauthenticated' })
  }

  const supabaseUrl = Deno.env.get('SUPABASE_URL') ?? 'http://127.0.0.1:54321'
  const anonKey = Deno.env.get('SUPABASE_ANON_KEY') ?? Deno.env.get('SUPABASE_PUBLISHABLE_KEYS') ?? ''

  const userClient = createClient(supabaseUrl, anonKey, {
    global: { headers: { Authorization: authHeader } },
    auth: { persistSession: false, autoRefreshToken: false },
  })

  const { data: userData, error: userError } = await userClient.auth.getUser()
  if (userError || !userData.user) {
    return json(401, { error: 'unauthenticated' })
  }

  let payload: { organisation_id?: string; email?: string; role?: string }
  try {
    payload = await req.json()
  } catch {
    return json(400, { error: 'invalid_json' })
  }

  const organisationId = payload.organisation_id
  const email = payload.email?.trim().toLowerCase()
  const role = payload.role

  if (!organisationId || !email || !role) {
    return json(400, { error: 'invalid_input' })
  }

  if (!['admin', 'member', 'guest'].includes(role)) {
    return json(400, { error: 'invalid_role' })
  }

  const token = randomToken()
  const hashHex = await sha256Hex(token)
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()

  const { data, error } = await userClient.rpc('create_invitation', {
    _organisation_id: organisationId,
    _email: email,
    _intended_role: role,
    _token_hash_hex: hashHex,
    _expires_at: expiresAt,
  })

  if (error) {
    const denied = /not authorized|not authenticated|invalid/i.test(error.message)
    return json(denied ? 403 : 400, { error: error.message })
  }

  const site = Deno.env.get('SITE_URL') ?? 'http://127.0.0.1:3000'
  return json(200, {
    invitation_id: data?.id,
    email,
    organisation_id: organisationId,
    expires_at: expiresAt,
    invite_url: `${site}/accept-invite?token=${token}`,
    note: 'Development-only invite URL. Production must send this token over email and never log it.',
  })
})
