import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import {
  pbkdf2Hash,
  sha256,
  corsHeaders,
  generatePin,
  generateSalt,
} from '../_shared/crypto.ts'

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  try {
    const body = await req.json()
    const { eventCode, adminPin, action } = body

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

    // Acciones autenticadas (verifican admin PIN internamente)
    if (action === 'list_participants' || action === 'reset_participant_pin') {
      const { participantId } = body
      if (!participantId) return new Response(
        JSON.stringify({ ok: false, error: 'Falta participantId' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )

      const supabase = createClient(
        Deno.env.get('SUPABASE_URL')!,
        Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
      )

      // Verificar que el evento existe y el admin PIN es correcto
      const { data: event } = await supabase
        .from('events')
        .select('id, admin_pin_hash, admin_pin_salt')
        .eq('code', eventCode.toUpperCase())
        .maybeSingle()

      if (!event) return new Response(
        JSON.stringify({ ok: false, error: 'Evento no encontrado' }),
        { status: 404, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )

      const pinHash = await pbkdf2Hash(adminPin, event.admin_pin_salt, 200_000)
      if (pinHash !== event.admin_pin_hash) return new Response(
        JSON.stringify({ ok: false, error: 'PIN admin incorrecto' }),
        { status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )

      // ── list_participants ──────────────────────────────
      if (action === 'list_participants') {
        const { data: participants, error: listErr } = await supabase
          .from('participants')
          .select('id, name, pin_changed, revealed')
          .eq('event_id', event.id)
          .order('name')

        if (listErr) throw listErr

        return new Response(
          JSON.stringify({ ok: true, participants }),
          { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        )
      }

      // ── reset_participant_pin ──────────────────────────
      const { participantId } = body
      if (!participantId) return new Response(
        JSON.stringify({ ok: false, error: 'Falta participantId' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )

      // Generar nuevo PIN y hashearlo
      const newPin = generatePin()
      const newSalt = generateSalt()
      const newHash = await pbkdf2Hash(newPin, newSalt, 200_000)

      const { error: updateErr } = await supabase
        .from('participants')
        .update({
          pin_hash: newHash,
          pin_salt: newSalt,
          pin_changed: false,
          revealed: false,
        })
        .eq('id', participantId)
        .eq('event_id', event.id)

      if (updateErr) throw updateErr

      return new Response(
        JSON.stringify({ ok: true, newPin }),
        { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
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
