import { createClient } from "npm:@supabase/supabase-js@2";
import {
  corsHeaders,
  generateCode,
  generatePin,
  generateSalt,
  pbkdf2Hash,
} from "../_shared/crypto.ts";

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { eventName, deliveryDate, maxAmount, participants } = await req.json();

    // ── Validaciones ────────────────────────────────────
    if (!eventName?.trim()) {
      return err(400, "Falta el nombre del evento");
    }
    if (!Array.isArray(participants) || participants.length < 3) {
      return err(400, "Se necesitan al menos 3 participantes para el sorteo");
    }
    if (participants.length > 100) {
      return err(400, "El máximo es 100 participantes por evento");
    }

    // Verificar nombres únicos
    const names: string[] = participants.map((p: { name: string }) => p.name?.trim()).filter(Boolean);
    if (names.length !== participants.length) {
      return err(400, "Todos los participantes deben tener nombre");
    }
    const uniqueNames = new Set(names);
    if (uniqueNames.size !== names.length) {
      return err(400, "Hay nombres repetidos en la lista");
    }

    // ── Supabase (service_role) ─────────────────────────
    const supabase = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
    );

    // ── Generar código único de evento ──────────────────
    let code: string;
    let codeExists = true;
    let attempts = 0;
    do {
      code = generateCode(6);
      const { data } = await supabase
        .from("events")
        .select("id")
        .eq("code", code)
        .maybeSingle();
      codeExists = !!data;
      if (++attempts > 10) throw new Error("No se pudo generar código único");
    } while (codeExists);

    // ── PIN admin ───────────────────────────────────────
    const adminPin = generatePin();
    const adminSalt = generateSalt();
    const adminPinHash = await pbkdf2Hash(adminPin, adminSalt, 200_000);

    // ── PINs de participantes ───────────────────────────
    const participantData = await Promise.all(
      names.map(async (name) => {
        const pin = generatePin();
        const pinSalt = generateSalt();
        const pinHash = await pbkdf2Hash(pin, pinSalt, 200_000);
        return { name, pin, pinHash, pinSalt };
      })
    );

    // ── Insertar evento ─────────────────────────────────
    const { data: event, error: eventErr } = await supabase
      .from("events")
      .insert({
        code,
        name: eventName.trim(),
        delivery_date: deliveryDate || null,
        max_amount: maxAmount ? parseInt(maxAmount) : null,
        admin_pin_hash: adminPinHash,
        admin_pin_salt: adminSalt,
      })
      .select("id")
      .single();

    if (eventErr) throw eventErr;

    // ── Insertar participantes ──────────────────────────
    const { error: partErr } = await supabase.from("participants").insert(
      participantData.map(({ name, pinHash, pinSalt }) => ({
        event_id: event.id,
        name,
        pin_hash: pinHash,
        pin_salt: pinSalt,
      }))
    );

    if (partErr) throw partErr;

    // ── Respuesta: PINs en texto claro UNA SOLA VEZ ────
    // Después de esta respuesta, los PINs no se pueden recuperar.
    return new Response(
      JSON.stringify({
        ok: true,
        eventCode: code,
        eventId: event.id,
        adminPin,
        participants: participantData.map(({ name, pin }) => ({ name, pin })),
      }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (e) {
    console.error("[create-event]", e);
    return err(500, "Algo salió mal. Intenta de nuevo.");
  }
});

function err(status: number, message: string) {
  return new Response(JSON.stringify({ ok: false, error: message }), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}
