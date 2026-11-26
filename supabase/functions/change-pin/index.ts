import { createClient } from "npm:@supabase/supabase-js@2";
import {
  corsHeaders,
  pbkdf2Hash,
  generateSalt,
} from "../_shared/crypto.ts";

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { eventCode, participantId, currentPin, newPin } = await req.json();

    if (!eventCode || !participantId || !currentPin || !newPin) {
      return err(400, "Faltan datos");
    }

    if (!/^\d{4}$/.test(currentPin) || !/^\d{4}$/.test(newPin)) {
      return err(400, "Los PINs deben ser de 4 dígitos");
    }

    if (currentPin === newPin) {
      return err(400, "El nuevo PIN debe ser diferente al actual");
    }

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
    );

    // ── Obtener participante ────────────────────────────
    const { data: participant, error: partErr } = await supabase
      .from("participants")
      .select("id, event_id, name, pin_hash, pin_salt, assignment_encrypted, assignment_iv, assignment_salt, pin_changed")
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

    if (!event.drawn) {
      return err(400, "El sorteo todavía no se ha realizado");
    }

    // ── Verificar PIN actual ────────────────────────────
    const computedHash = await pbkdf2Hash(currentPin, participant.pin_salt, 200_000);
    if (computedHash !== participant.pin_hash) {
      return err(401, "PIN actual incorrecto");
    }

    // ── Hashear nuevo PIN ───────────────────────────────
    const newSalt = generateSalt();
    const newHash = await pbkdf2Hash(newPin, newSalt, 200_000);

    // ── Actualizar participante ─────────────────────────
    const { error: updateErr } = await supabase
      .from("participants")
      .update({
        pin_hash: newHash,
        pin_salt: newSalt,
        pin_changed: true,
        revealed: true,
      })
      .eq("id", participant.id);

    if (updateErr) throw updateErr;

    // ── Descifrar asignación ────────────────────────────
    const serverSecret = Deno.env.get("ASSIGNMENT_HMAC_SECRET");
    if (!serverSecret) throw new Error("Falta ASSIGNMENT_HMAC_SECRET en env");

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

    return new Response(
      JSON.stringify({ ok: true, assigneeName }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (e) {
    console.error("[change-pin]", e);
    return err(500, "Algo salió mal. Intenta de nuevo.");
  }
});

function err(status: number, message: string) {
  return new Response(JSON.stringify({ ok: false, error: message }), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}
