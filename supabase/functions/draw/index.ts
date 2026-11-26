import { createClient } from "npm:@supabase/supabase-js@2";
import {
  corsHeaders,
  generateSalt,
  pbkdf2Hash,
  sha256,
  deriveAesKey,
  aesEncrypt,
  generateDerangement,
} from "../_shared/crypto.ts";

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    // ── Rate limiting: obtener IP hasheada ──────────────
    const ip =
      req.headers.get("x-forwarded-for")?.split(",")[0].trim() ??
      req.headers.get("x-real-ip") ??
      "unknown";
    const ipHash = await sha256(ip);

    const { eventCode, adminPin } = await req.json();

    if (!eventCode || !adminPin) {
      return err(400, "Faltan datos");
    }

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
    );

    // ── Obtener evento ──────────────────────────────────
    const { data: event, error: eventErr } = await supabase
      .from("events")
      .select("id, drawn, admin_pin_hash, admin_pin_salt")
      .eq("code", eventCode.toUpperCase())
      .maybeSingle();

    if (eventErr || !event) {
      return err(404, "Evento no encontrado");
    }

    // ── Rate limiting server-side ───────────────────────
    const { data: allowed } = await supabase.rpc("check_and_record_attempt", {
      p_event_id: event.id,
      p_participant_id: null, // null = admin
      p_ip_hash: ipHash,
      p_max_attempts: 5,
      p_block_minutes: 15,
    });

    if (!allowed) {
      return err(429, "Demasiados intentos fallidos. Espérate 15 minutos y vuelve a intentar.");
    }

    // ── Verificar PIN admin ─────────────────────────────
    const computedHash = await pbkdf2Hash(adminPin, event.admin_pin_salt, 200_000);
    if (computedHash !== event.admin_pin_hash) {
      return err(401, "PIN incorrecto");
    }

    // PIN correcto → resetear intentos
    await supabase.rpc("reset_attempts", {
      p_event_id: event.id,
      p_participant_id: null,
      p_ip_hash: ipHash,
    });

    // ── Verificar que no se haya sorteado (con bloqueo) ─
    const { data: canDraw } = await supabase.rpc("lock_event_for_draw", {
      p_event_id: event.id,
    });

    if (!canDraw) {
      return err(409, "El sorteo ya se realizó. No se puede volver a sortear.");
    }

    // ── Obtener participantes ───────────────────────────
    const { data: participants, error: partErr } = await supabase
      .from("participants")
      .select("id, name, pin_salt")
      .eq("event_id", event.id)
      .order("created_at");

    if (partErr || !participants || participants.length < 3) {
      return err(400, "Se necesitan al menos 3 participantes para sortear");
    }

    // ── Generar derangement (sorteo sin auto-asignación) ─
    const derangement = generateDerangement(participants.length);
    // derangement[i] = índice del amigo secreto de participants[i]

    const serverSecret = Deno.env.get("ASSIGNMENT_HMAC_SECRET");
    if (!serverSecret) throw new Error("Falta ASSIGNMENT_HMAC_SECRET en env");

    // ── Cifrar asignaciones ─────────────────────────────
    // Clave = PBKDF2(PIN_participante + "|" + serverSecret, assignment_salt)
    // Como NO tenemos el PIN en texto claro, usamos el pin_salt del participante
    // para generar un assignment_salt único, y derivamos la clave con:
    // - La verificación del PIN ocurre en verify-pin
    // - El descifrado también ocurre en verify-pin (en servidor)
    // Por lo tanto aquí usamos una clave temporal derivada del serverSecret + participant_id
    // que luego en verify-pin se recalcula igual.
    const updates = await Promise.all(
      participants.map(async (participant, i) => {
        const assignee = participants[derangement[i]];
        const assignmentSalt = generateSalt();

        // Clave derivada de: participant_id + serverSecret + assignment_salt
        // Esto permite que verify-pin recalcule la misma clave sin el PIN,
        // ya que la verificación del PIN ocurre primero en verify-pin.
        // La clave NO depende del PIN — el PIN es solo el candado de acceso a verify-pin.
        // El cifrado real está protegido por: rate limiting + verificación PIN + serverSecret.
        const keyMaterial = participant.id + "|" + serverSecret;
        const enc = new TextEncoder();
        const keyBase = await crypto.subtle.importKey(
          "raw",
          enc.encode(keyMaterial),
          "PBKDF2",
          false,
          ["deriveKey"]
        );
        const aesKey = await crypto.subtle.deriveKey(
          {
            name: "PBKDF2",
            hash: "SHA-256",
            salt: new TextEncoder().encode(assignmentSalt),
            iterations: 150_000,
          },
          keyBase,
          { name: "AES-GCM", length: 256 },
          false,
          ["encrypt", "decrypt"]
        );

        const { encrypted, iv } = await aesEncrypt(assignee.name, aesKey);

        return {
          id: participant.id,
          assignment_encrypted: encrypted,
          assignment_iv: iv,
          assignment_salt: assignmentSalt,
        };
      })
    );

    // ── Guardar asignaciones cifradas ───────────────────
    for (const update of updates) {
      await supabase
        .from("participants")
        .update({
          assignment_encrypted: update.assignment_encrypted,
          assignment_iv: update.assignment_iv,
          assignment_salt: update.assignment_salt,
        })
        .eq("id", update.id);
    }

    // ── Marcar evento como sorteado ─────────────────────
    await supabase
      .from("events")
      .update({ drawn: true })
      .eq("id", event.id);

    return new Response(
      JSON.stringify({ ok: true, message: "¡Sorteo realizado! 🎁" }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (e) {
    console.error("[draw]", e);
    return err(500, "Algo salió mal en el sorteo. Intenta de nuevo.");
  }
});

function err(status: number, message: string) {
  return new Response(JSON.stringify({ ok: false, error: message }), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}
