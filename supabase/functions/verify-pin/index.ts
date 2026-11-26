import { createClient } from "npm:@supabase/supabase-js@2";
import {
  corsHeaders,
  pbkdf2Hash,
  sha256,
} from "../_shared/crypto.ts";

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const ip =
      req.headers.get("x-forwarded-for")?.split(",")[0].trim() ??
      req.headers.get("x-real-ip") ??
      "unknown";
    const ipHash = await sha256(ip);

    const { eventCode, participantId, pin } = await req.json();

    if (!eventCode || !participantId || !pin) {
      return err(400, "Faltan datos");
    }

    if (!/^\d{4}$/.test(pin)) {
      return err(400, "El PIN debe ser de 4 dígitos");
    }

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
    );

    // ── Obtener participante con su evento ──────────────
    const { data: participant, error: partErr } = await supabase
      .from("participants")
      .select("id, event_id, name, pin_hash, pin_salt, assignment_encrypted, assignment_iv, assignment_salt")
      .eq("id", participantId)
      .maybeSingle();

    if (partErr || !participant) {
      return err(404, "Participante no encontrado");
    }

    // ── Verificar que el evento coincide ─────────────────
    const { data: event, error: eventErr } = await supabase
      .from("events")
      .select("id, drawn")
      .eq("code", eventCode.toUpperCase())
      .eq("id", participant.event_id)
      .maybeSingle();

    if (eventErr || !event) {
      return err(404, "Evento no encontrado");
    }

    // ── Rate limiting ───────────────────────────────────
    const { data: allowed } = await supabase.rpc("check_and_record_attempt", {
      p_event_id: event.id,
      p_participant_id: participantId,
      p_ip_hash: ipHash,
      p_max_attempts: 5,
      p_block_minutes: 15,
    });

    if (!allowed) {
      return err(429, "Demasiados intentos. Espérate 15 minutos, po.");
    }

    // ── Sorteo realizado? ───────────────────────────────
    if (!event.drawn) {
      return err(400, "El sorteo todavía no se ha realizado. Espera que el organizador lo haga.");
    }

    // ── Verificar PIN ───────────────────────────────────
    const computedHash = await pbkdf2Hash(pin, participant.pin_salt, 200_000);
    if (computedHash !== participant.pin_hash) {
      return err(401, "PIN incorrecto. Fíjate bien, puede tener ceros a la izquierda.");
    }

    // ── PIN correcto: resetear intentos ─────────────────
    await supabase.rpc("reset_attempts", {
      p_event_id: event.id,
      p_participant_id: participantId,
      p_ip_hash: ipHash,
    });

    // ── Descifrar asignación en el servidor ─────────────
    const serverSecret = Deno.env.get("ASSIGNMENT_HMAC_SECRET");
    if (!serverSecret) throw new Error("Falta ASSIGNMENT_HMAC_SECRET en env");

    // Recalcular la misma clave que usó draw/index.ts
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
        salt: enc.encode(participant.assignment_salt),
        iterations: 150_000,
      },
      keyBase,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );

    // Descifrar
    function hexToBytes(hex: string): Uint8Array {
      const bytes = new Uint8Array(hex.length / 2);
      for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
      }
      return bytes;
    }

    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: hexToBytes(participant.assignment_iv) },
      aesKey,
      hexToBytes(participant.assignment_encrypted)
    );

    const assigneeName = new TextDecoder().decode(decrypted);

    // ── Respuesta: solo el nombre, nada más ─────────────
    return new Response(
      JSON.stringify({ ok: true, assigneeName }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (e) {
    console.error("[verify-pin]", e);
    return err(500, "Algo salió mal. Intenta de nuevo.");
  }
});

function err(status: number, message: string) {
  return new Response(JSON.stringify({ ok: false, error: message }), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}
