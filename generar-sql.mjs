/**
 * Genera el SQL de inserción con los datos cifrados.
 * El resultado hay que pegarlo en el SQL Editor de Supabase.
 */

import { webcrypto } from 'node:crypto';
const crypto = webcrypto;

const PARTICIPANTES = [
  { id: 'maru',       nombre: 'Maru',        pin: '3847' },
  { id: 'pricila',    nombre: 'Pricila',     pin: '6192' },
  { id: 'ines',       nombre: 'Inés',        pin: '5074' },
  { id: 'bernardo',   nombre: 'Bernardo',    pin: '9361' },
  { id: 'claudio',    nombre: 'Claudio',     pin: '2815' },
  { id: 'juancarlos', nombre: 'Juan Carlos', pin: '7430' },
  { id: 'cecilia',    nombre: 'Cecilia',     pin: '4968' },
  { id: 'alvaro',     nombre: 'Álvaro',      pin: '1253' },
];

// Sorteo fijo (ya aprobado):
const ASIGNACIONES = {
  'maru':       'Cecilia',
  'pricila':    'Inés',
  'ines':       'Bernardo',
  'bernardo':   'Maru',
  'claudio':    'Álvaro',
  'juancarlos': 'Pricila',
  'cecilia':    'Juan Carlos',
  'alvaro':     'Claudio',
};

async function sha256(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
}

async function getKey(pin) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(pin.padEnd(16,'0')),
    'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name:'PBKDF2', salt: new TextEncoder().encode('amigo-secreto-2026'), iterations:100000, hash:'SHA-256' },
    keyMaterial,
    { name:'AES-GCM', length:256 }, false, ['encrypt']
  );
}

async function cifrar(texto, pin) {
  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const key = await getKey(pin);
  const enc = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key, new TextEncoder().encode(texto));
  const combined = new Uint8Array(iv.byteLength + enc.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(enc), iv.byteLength);
  return btoa(String.fromCharCode(...combined));
}

async function main() {
  const values = [];

  for (const p of PARTICIPANTES) {
    const pinHash = await sha256(p.pin);
    const dest = ASIGNACIONES[p.id];
    const enc  = await cifrar(dest, p.pin);
    // Escape single quotes for SQL
    const nombre = p.nombre.replace(/'/g, "''");
    values.push(`('${p.id}', '${nombre}', '${pinHash}', '${enc}', false)`);
  }

  const sql = `-- Crear tabla si no existe
CREATE TABLE IF NOT EXISTS amigo_secreto_2026 (
  id               TEXT PRIMARY KEY,
  nombre           TEXT NOT NULL,
  pin_hash         TEXT NOT NULL,
  destinatario_enc TEXT DEFAULT NULL,
  visto            BOOLEAN DEFAULT FALSE,
  created_at       TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE amigo_secreto_2026 ENABLE ROW LEVEL SECURITY;

-- Eliminar políticas existentes si las hay
DROP POLICY IF EXISTS "anon lee" ON amigo_secreto_2026;
DROP POLICY IF EXISTS "anon actualiza" ON amigo_secreto_2026;
DROP POLICY IF EXISTS "anon inserta" ON amigo_secreto_2026;

CREATE POLICY "anon lee" ON amigo_secreto_2026 FOR SELECT TO anon USING (true);
CREATE POLICY "anon actualiza" ON amigo_secreto_2026 FOR UPDATE TO anon USING (true) WITH CHECK (true);
CREATE POLICY "anon inserta" ON amigo_secreto_2026 FOR INSERT TO anon WITH CHECK (true);

-- Insertar datos del sorteo
INSERT INTO amigo_secreto_2026 (id, nombre, pin_hash, destinatario_enc, visto)
VALUES
${values.join(',\n')}
ON CONFLICT (id) DO UPDATE SET
  pin_hash         = EXCLUDED.pin_hash,
  destinatario_enc = EXCLUDED.destinatario_enc,
  visto            = FALSE;

-- Verificar
SELECT id, nombre, visto FROM amigo_secreto_2026 ORDER BY created_at;
`;

  console.log(sql);

  // También mostrar el sorteo
  console.error('\n📝 SORTEO (solo para Claudio):');
  for (const p of PARTICIPANTES) {
    console.error(`   ${p.nombre.padEnd(12)} → ${ASIGNACIONES[p.id]}`);
  }
}

main().catch(console.error);
