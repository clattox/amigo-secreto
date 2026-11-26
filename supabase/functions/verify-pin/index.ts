import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import {
  pbkdf2Hash,
  sha256,
  deriveAesKey,
  aesDecrypt,
  corsHeaders,
} from '../_shared/crypto.ts'

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  try {
    const { eventCode, participantId, pin } = await req.json()

    if (!eventCode || !participantId || !pin) {
      return new Response(
        JSON.stringify({ ok: false, error: 'Faltan datos requeridos' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    if (!/^\d{4}$/.test(pin)) {
      return new Response(
        JSON.stringify({ ok: false, error: 'PIN inválido' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    const clientIp =
      req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ??
      req.headers.get('x-real-ip') ?? 'unknown'
    const ipHash = await sha256(clientIp)

    const supabase = createClient(
      Deno.env.get('SUPABASE_URL')!,
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
    )

    const { data: participant, error: partError } = await supabase
      .from('participants')
      .select('id, event_id, name, pin_hash, pin_salt, assignment_encrypted, assignment_iv, assignment_salt')
      .eq('id', participantId)
      .maybeSingle()

    if (partError || !participant) {
      return new Response(
        JSON.stringify({ ok: false, error: 'Participante no encontrado' }),
        { status: 404, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    const { data: event, error: eventError } = await supabase
      .from('events')
      .select('id, code, drawn')
      .eq('id', participant.event_id)
      .maybeSingle()

    if (eventError || !event || event.code !== eventCode.toUpperCase()) {
      return new Response(
        JSON.stringify({ ok: false, error: 'Evento no válido' }),
        { status: 404, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    if (!event.drawn) {
      return new Response(
        JSON.stringify({ ok: false, error: 'El sorteo todavía no se ha realizado. Espera que el organizador lo haga.' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    // Rate limiting
    const { data: rateCheck } = await supabase.rpc('check_and_record_attempt', {
      p_event_id: event.id,
      p_participant_id: participantId,
      p_ip_hash: ipHash,
      p_max_attempts: 5,
      p_block_minutes: 15,
    })

    if (!rateCheck?.allowed && rateCheck !== true) {
      const mins = Math.ceil((rateCheck?.retry_after_seconds ?? 900) / 60)
      return new Response(
        JSON.stringify({ ok: false, error: `Demasiados intentos fallidos. Espera ${mins} minuto${mins !== 1 ? 's' : ''} antes de intentar de nuevo.` }),
        { status: 429, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    // Verificar PIN
    const pinHash = await pbkdf2Hash(pin, participant.pin_salt, 200_000)
    if (pinHash !== participant.pin_hash) {
      return new Response(
        JSON.stringify({ ok: false, error: 'PIN incorrecto. Revisa el mensaje que te mandó el organizador.' }),
        { status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    await supabase.rpc('reset_attempts', {
      p_event_id: event.id,
      p_participant_id: participantId,
      p_ip_hash: ipHash,
    })

    // Descifrar asignación en el servidor
    const hmacSecret = Deno.env.get('ASSIGNMENT_HMAC_SECRET')!
    const key = await deriveAesKey(participant.id, participant.assignment_salt, hmacSecret)
    const assigneeName = await aesDecrypt(participant.assignment_encrypted, participant.assignment_iv, key)

    return new Response(
      JSON.stringify({ ok: true, assigneeName }),
      { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    )
  } catch (err) {
    console.error('verify-pin error:', err)
    return new Response(
      JSON.stringify({ ok: false, error: 'Error interno del servidor' }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    )
  }
})
