import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import {
  pbkdf2Hash,
  sha256,
  corsHeaders,
} from '../_shared/crypto.ts'

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  try {
    const { eventCode, adminPin } = await req.json()

    // Validación básica
    if (!eventCode || !adminPin) {
      return new Response(
        JSON.stringify({ ok: false, error: 'Faltan datos requeridos' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    if (!/^\d{4}$/.test(adminPin)) {
      return new Response(
        JSON.stringify({ ok: false, error: 'El PIN debe ser de 4 dígitos' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    // Hash IP
    const clientIp =
      req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ??
      req.headers.get('x-real-ip') ??
      'unknown'
    const ipHash = await sha256(clientIp)

    const supabase = createClient(
      Deno.env.get('SUPABASE_URL')!,
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
    )

    // Buscar evento
    const { data: event, error: eventError } = await supabase
      .from('events')
      .select('id, code, name, drawn, admin_pin_hash, admin_pin_salt')
      .eq('code', eventCode.toUpperCase())
      .maybeSingle()

    if (eventError || !event) {
      return new Response(
        JSON.stringify({ ok: false, error: 'Evento no encontrado' }),
        { status: 404, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    // Rate limiting: intentos admin (participant_id = null)
    const { data: rateCheck, error: rateError } = await supabase.rpc(
      'check_and_record_attempt',
      {
        p_event_id: event.id,
        p_participant_id: null,
        p_ip_hash: ipHash,
        p_max_attempts: 5,
        p_block_minutes: 15,
      }
    )

    if (rateError) {
      return new Response(
        JSON.stringify({ ok: false, error: 'Error interno del servidor' }),
        { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    if (!rateCheck.allowed) {
      const mins = Math.ceil(rateCheck.retry_after_seconds / 60)
      return new Response(
        JSON.stringify({
          ok: false,
          error: `Demasiados intentos fallidos. Espera ${mins} minuto${mins !== 1 ? 's' : ''} antes de intentar de nuevo.`,
        }),
        { status: 429, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    // Verificar PIN admin
    const pinHash = await pbkdf2Hash(adminPin, event.admin_pin_salt, 200_000)

    if (pinHash !== event.admin_pin_hash) {
      return new Response(
        JSON.stringify({ ok: false, error: 'PIN incorrecto. Revisa el papel donde lo anotaste.' }),
        { status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    // PIN correcto → resetear intentos
    await supabase.rpc('reset_attempts', {
      p_event_id: event.id,
      p_participant_id: null,
      p_ip_hash: ipHash,
    })

    return new Response(
      JSON.stringify({
        ok: true,
        drawn: event.drawn,
        eventName: event.name,
      }),
      { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    )
  } catch (err) {
    console.error('verify-admin-pin error:', err)
    return new Response(
      JSON.stringify({ ok: false, error: 'Error interno del servidor' }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    )
  }
})
