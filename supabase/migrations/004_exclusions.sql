-- Tabla de exclusiones: pares de participantes que NO pueden quedar juntos en el sorteo
-- La restricción es bidireccional: si A no puede regalarle a B, tampoco B puede regalarle a A.

CREATE TABLE IF NOT EXISTS exclusions (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id      UUID NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  participant_a_id UUID NOT NULL REFERENCES participants(id) ON DELETE CASCADE,
  participant_b_id UUID NOT NULL REFERENCES participants(id) ON DELETE CASCADE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

  -- Evitar duplicados exactos
  CONSTRAINT exclusions_unique UNIQUE (event_id, participant_a_id, participant_b_id),
  -- Evitar auto-exclusión
  CONSTRAINT exclusions_no_self CHECK (participant_a_id <> participant_b_id)
);

-- Índice para consultar exclusiones de un evento rápido
CREATE INDEX IF NOT EXISTS exclusions_event_idx ON exclusions(event_id);

-- RLS: solo service_role puede leer/escribir (Edge Functions usan service_role)
ALTER TABLE exclusions ENABLE ROW LEVEL SECURITY;

-- No permitir acceso anon ni autenticado normal (solo service_role bypasea RLS)
-- Por defecto con RLS habilitado y sin policies = nadie puede acceder excepto service_role
