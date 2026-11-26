-- ============================================================
-- Amigo Secreto ClauNet — Schema v2.0
-- Sistema multi-evento
-- ============================================================

-- ── TABLA: events ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS events (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  code            TEXT UNIQUE NOT NULL,       -- 6 chars: URL pública /#/e/CODIGO
  name            TEXT NOT NULL,
  delivery_date   DATE,
  max_amount      INTEGER,                    -- CLP, sin decimales
  drawn           BOOLEAN NOT NULL DEFAULT FALSE,
  created_at      TIMESTAMPTZ DEFAULT NOW(),

  -- PIN admin: solo hash PBKDF2, NUNCA el PIN real
  admin_pin_hash  TEXT NOT NULL,
  admin_pin_salt  TEXT NOT NULL
);

-- ── TABLA: participants ────────────────────────────────────
CREATE TABLE IF NOT EXISTS participants (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id              UUID NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  name                  TEXT NOT NULL,

  -- PIN individual: solo hash PBKDF2
  pin_hash              TEXT NOT NULL,
  pin_salt              TEXT NOT NULL,

  -- Asignación cifrada con AES-GCM
  -- Clave derivada de PIN + HMAC_SECRET del servidor (nunca en DB)
  assignment_encrypted  TEXT,               -- null hasta sorteo
  assignment_iv         TEXT,
  assignment_salt       TEXT,

  created_at            TIMESTAMPTZ DEFAULT NOW(),

  UNIQUE(event_id, name)
);

-- ── TABLA: pin_attempts (rate limiting server-side) ────────
CREATE TABLE IF NOT EXISTS pin_attempts (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id        UUID NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  participant_id  UUID,                      -- null = intento admin
  ip_hash         TEXT NOT NULL,             -- SHA-256 de IP, nunca la IP real
  attempts        INTEGER NOT NULL DEFAULT 1,
  blocked_until   TIMESTAMPTZ,
  last_attempt    TIMESTAMPTZ DEFAULT NOW(),

  UNIQUE(event_id, participant_id, ip_hash)
);

-- ── ÍNDICES ────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_events_code ON events(code);
CREATE INDEX IF NOT EXISTS idx_participants_event ON participants(event_id);
CREATE INDEX IF NOT EXISTS idx_attempts_lookup ON pin_attempts(event_id, participant_id, ip_hash);

-- ── VISTAS PÚBLICAS (solo columnas no sensibles) ───────────
CREATE OR REPLACE VIEW public_events AS
  SELECT id, code, name, delivery_date, max_amount, drawn, created_at
  FROM events;

CREATE OR REPLACE VIEW public_participants AS
  SELECT id, event_id, name, created_at
  FROM participants;

-- ── RLS ───────────────────────────────────────────────────
ALTER TABLE events ENABLE ROW LEVEL SECURITY;
ALTER TABLE participants ENABLE ROW LEVEL SECURITY;
ALTER TABLE pin_attempts ENABLE ROW LEVEL SECURITY;

-- events: lectura pública de columnas no sensibles vía vista
-- La tabla base solo es accesible por service_role (Edge Functions)
CREATE POLICY events_deny_all_anon ON events
  FOR ALL TO anon USING (false);

-- participants: ídem
CREATE POLICY participants_deny_all_anon ON participants
  FOR ALL TO anon USING (false);

-- pin_attempts: solo service_role
-- (no policy = denegado para anon por defecto con RLS habilitado)

-- Acceso a las vistas para anon (solo lectura, solo columnas seguras)
GRANT SELECT ON public_events TO anon;
GRANT SELECT ON public_participants TO anon;

-- ── FUNCIÓN: check_and_record_attempt ─────────────────────
-- Llamada desde Edge Functions vía service_role
-- Retorna: TRUE si el intento está permitido, FALSE si bloqueado
CREATE OR REPLACE FUNCTION check_and_record_attempt(
  p_event_id      UUID,
  p_participant_id UUID,    -- NULL para admin
  p_ip_hash       TEXT,
  p_max_attempts  INT DEFAULT 5,
  p_block_minutes INT DEFAULT 15
) RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_attempts      INT;
  v_blocked_until TIMESTAMPTZ;
BEGIN
  SELECT attempts, blocked_until
  INTO v_attempts, v_blocked_until
  FROM pin_attempts
  WHERE event_id = p_event_id
    AND ip_hash   = p_ip_hash
    AND (
      (p_participant_id IS NULL     AND participant_id IS NULL)
      OR participant_id = p_participant_id
    );

  -- Bloqueado y sin expirar → rechazar
  IF v_blocked_until IS NOT NULL AND v_blocked_until > NOW() THEN
    RETURN FALSE;
  END IF;

  -- Bloqueo expirado → resetear
  IF v_blocked_until IS NOT NULL AND v_blocked_until <= NOW() THEN
    UPDATE pin_attempts
    SET attempts = 1, blocked_until = NULL, last_attempt = NOW()
    WHERE event_id = p_event_id
      AND ip_hash   = p_ip_hash
      AND (
        (p_participant_id IS NULL AND participant_id IS NULL)
        OR participant_id = p_participant_id
      );
    RETURN TRUE;
  END IF;

  -- Sin registro previo → insertar con 1 intento
  IF v_attempts IS NULL THEN
    INSERT INTO pin_attempts(event_id, participant_id, ip_hash, attempts)
    VALUES (p_event_id, p_participant_id, p_ip_hash, 1)
    ON CONFLICT (event_id, participant_id, ip_hash) DO NOTHING;
    RETURN TRUE;
  END IF;

  -- Incrementar intentos
  v_attempts := v_attempts + 1;

  IF v_attempts >= p_max_attempts THEN
    -- Bloquear
    UPDATE pin_attempts
    SET attempts = v_attempts,
        blocked_until = NOW() + (p_block_minutes || ' minutes')::INTERVAL,
        last_attempt = NOW()
    WHERE event_id = p_event_id
      AND ip_hash   = p_ip_hash
      AND (
        (p_participant_id IS NULL AND participant_id IS NULL)
        OR participant_id = p_participant_id
      );
    RETURN FALSE;
  ELSE
    UPDATE pin_attempts
    SET attempts = v_attempts, last_attempt = NOW()
    WHERE event_id = p_event_id
      AND ip_hash   = p_ip_hash
      AND (
        (p_participant_id IS NULL AND participant_id IS NULL)
        OR participant_id = p_participant_id
      );
    RETURN TRUE;
  END IF;
END;
$$;

-- ── FUNCIÓN: reset_attempts (PIN correcto) ─────────────────
CREATE OR REPLACE FUNCTION reset_attempts(
  p_event_id      UUID,
  p_participant_id UUID,
  p_ip_hash       TEXT
) RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  DELETE FROM pin_attempts
  WHERE event_id = p_event_id
    AND ip_hash   = p_ip_hash
    AND (
      (p_participant_id IS NULL AND participant_id IS NULL)
      OR participant_id = p_participant_id
    );
END;
$$;

-- ── FUNCIÓN: lock_event_for_draw (previene condición de carrera) ──
CREATE OR REPLACE FUNCTION lock_event_for_draw(p_event_id UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_drawn BOOLEAN;
BEGIN
  SELECT drawn INTO v_drawn
  FROM events
  WHERE id = p_event_id
  FOR UPDATE;  -- bloqueo pesimista

  IF v_drawn THEN
    RETURN FALSE;  -- ya sorteado
  END IF;

  RETURN TRUE;  -- ok para sortear
END;
$$;
