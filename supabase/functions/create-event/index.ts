import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import {
  generateCode,
  generatePin,
  generateSalt,
  pbkdf2Hash,
  sha256,
  corsHeaders,
} from '../_shared/crypto.ts'

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  try {
    const { eventName, deliveryDate, maxAmount, participants } = await req.json()

    if (!eventName?.trim()) {
      return new Response(
        JSON.stringify({ ok: false, error: 'El nombre del evento es obligatorio' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }
    if (!Array.isArray(participants) || participants.length < 3) {
      return new Response(
        JSON.stringify({ ok: false, error: 'Se necesitan al menos 3 participantes' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }
    if (participants.length > 100) {
      return new Response(
        JSON.stringify({ ok: false, error: 'Máximo 100 participantes' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    const names = participants.map((p: any) => p.name?.trim()).filter(Boolean)
    if (new Set(names).size !== names.length) {
      return new Response(
        JSON.stringify({ ok: false, error: 'Hay nombres duplicados' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    const supabase = createClient(
      Deno.env.get('SUPABASE_URL')!,
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
    )

    // Generar código único
    let code = ''
    for (let i = 0; i < 10; i++) {
      const candidate = generateCode(6)
      const { data } = await supabase.from('events').select('id').eq('code', candidate).maybeSingle()
      if (!data) { code = candidate; break }
    }
    if (!code) throw new Error('No se pudo generar código único')

    // PIN admin
    const adminPin = generatePin()
    const adminSalt = generateSalt()
    const adminHash = await pbkdf2Hash(adminPin, adminSalt, 200_000)

    // Crear evento
    const { data: event, error: eventError } = await supabase
      .from('events')
      .insert({
        code,
        name: eventName.trim(),
        delivery_date: deliveryDate || null,
        max_amount: maxAmount ? parseInt(maxAmount) : null,
        admin_pin_hash: adminHash,
        admin_pin_salt: adminSalt,
      })
      .select('id')
      .single()

    if (eventError) throw eventError

    // Crear participantes con PINs
    const participantResults = []
    for (const name of names) {
      const pin = generatePin()
      const salt = generateSalt()
      const hash = await pbkdf2Hash(pin, salt, 200_000)
      const { error } = await supabase.from('participants').insert({
        event_id: event.id,
        name,
        pin_hash: hash,
        pin_salt: salt,
      })
      if (error) throw error
      participantResults.push({ name, pin })
    }

    return new Response(
      JSON.stringify({
        ok: true,
        eventCode: code,
        eventId: event.id,
        adminPin,
        participants: participantResults,
      }),
      { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    )
  } catch (err) {
    console.error('create-event error:', err)
    return new Response(
      JSON.stringify({ ok: false, error: 'Error interno del servidor' }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    )
  }
})
