import { serve } from 'https://deno.land/std@0.168.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}

serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: CORS });

  try {
    const body = await req.json();
    const { action } = body;

    const sb = createClient(
      Deno.env.get('SUPABASE_URL')!,
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
    );

    // ── Verificar contraseña maestra ─────────────────────
    if (action === 'check_pass') {
      const adminPass = Deno.env.get('CLAUNET_ADMIN_PASS');
      if (!adminPass) return json({ ok: false, error: 'not_configured' });
      return json({ ok: body.pass === adminPass });
    }

    // ── Leer TOTP secret ─────────────────────────────────
    if (action === 'get_secret') {
      const { data } = await sb
        .from('claunet_admin_config')
        .select('value')
        .eq('key', 'totp_secret')
        .single();
      return json({ secret: data?.value ?? null });
    }

    // ── Guardar TOTP secret (setup inicial) ──────────────
    if (action === 'save_secret') {
      await sb
        .from('claunet_admin_config')
        .upsert({ key: 'totp_secret', value: body.secret });
      return json({ ok: true });
    }

    // ── Listar todos los eventos ─────────────────────────
    if (action === 'list_events') {
      const { data: events } = await sb
        .from('events')
        .select('id, code, name, delivery_date, drawn, created_at')
        .order('created_at', { ascending: false });

      const { data: parts } = await sb
        .from('participants')
        .select('event_id');

      const countMap: Record<string, number> = {};
      (parts || []).forEach((p: any) => {
        countMap[p.event_id] = (countMap[p.event_id] || 0) + 1;
      });

      const enriched = (events || []).map((e: any) => ({
        ...e,
        participant_count: countMap[e.id] || 0,
      }));

      return json({ events: enriched });
    }

    // ── Eliminar evento ──────────────────────────────────
    if (action === 'delete_event') {
      const { error } = await sb
        .from('events')
        .delete()
        .eq('id', body.event_id);
      if (error) return json({ ok: false, error: error.message }, 500);
      return json({ ok: true });
    }

    return json({ error: 'unknown action' }, 400);

  } catch (e) {
    return json({ error: String(e) }, 500);
  }
});
