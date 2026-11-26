-- ══════════════════════════════════════════════════
-- AMIGO SECRETO 2026 — Setup Supabase
-- Ejecutar en el SQL Editor de Supabase
-- ══════════════════════════════════════════════════

-- 1. Tabla principal
CREATE TABLE IF NOT EXISTS amigo_secreto_2026 (
  id            TEXT PRIMARY KEY,          -- slug del nombre: 'maru', 'ines', etc.
  nombre        TEXT NOT NULL,             -- nombre para mostrar
  pin_hash      TEXT NOT NULL,             -- SHA-256 del PIN de 4 dígitos
  destinatario_enc TEXT DEFAULT NULL,      -- nombre del asignado, cifrado con AES-GCM + PIN
  visto         BOOLEAN DEFAULT FALSE,     -- si ya reveló su asignado
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

-- 2. RLS
ALTER TABLE amigo_secreto_2026 ENABLE ROW LEVEL SECURITY;

-- Solo lectura pública (anon puede SELECT para verificar PIN y leer enc)
CREATE POLICY "anon lee" ON amigo_secreto_2026
  FOR SELECT TO anon USING (true);

-- Solo UPDATE de visto y destinatario_enc desde anon (el sorteo y la app)
CREATE POLICY "anon actualiza" ON amigo_secreto_2026
  FOR UPDATE TO anon USING (true) WITH CHECK (true);

-- INSERT solo para el setup inicial
CREATE POLICY "anon inserta" ON amigo_secreto_2026
  FOR INSERT TO anon WITH CHECK (true);


-- 3. Insertar participantes (PINs hasheados con SHA-256)
-- Los hashes se generan desde el script de setup (ver setup-pines.js)
-- Ejecutar DESPUÉS de correr el script setup-pines.js para obtener los hashes

-- Ejemplo (reemplazar con los hashes reales del script):
-- INSERT INTO amigo_secreto_2026 (id, nombre, pin_hash) VALUES
--   ('maru',       'Maru',        '<hash>'),
--   ('pricila',    'Pricila',     '<hash>'),
--   ('ines',       'Inés',        '<hash>'),
--   ('bernardo',   'Bernardo',    '<hash>'),
--   ('claudio',    'Claudio',     '<hash>'),
--   ('juancarlos', 'Juan Carlos', '<hash>'),
--   ('cecilia',    'Cecilia',     '<hash>'),
--   ('alvaro',     'Álvaro',      '<hash>');
