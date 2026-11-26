/**
 * AMIGO SECRETO 2026 — Script de setup y sorteo
 *
 * Este script:
 * 1. Genera los hashes SHA-256 de los PINs
 * 2. Realiza el sorteo (sin auto-asignación, sin duplicados)
 * 3. Cifra cada asignación con AES-GCM usando el PIN como clave
 * 4. Sube todo a Supabase
 *
 * Uso: node setup-sorteo.mjs
 */

import { webcrypto } from 'node:crypto';
const crypto = webcrypto;

// ══════════════════════════════════════════════════
// CONFIG — Supabase
// ══════════════════════════════════════════════════
const SB_URL = 'https://mcldbaubekjxpufmtrmk.supabase.co';
const SB_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im1jbGRiYXViZWtqeHB1Zm10cm1rIiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTI4ODY2NjcsImV4cCI6MjEwODQ2MjY2N30.ooSZNrkEDlICGsv77esUv-ZhxzzfW3ZASoqEXIVW1I4';
const TABLE  = 'amigo_secreto_2026';

// ══════════════════════════════════════════════════
// PARTICIPANTES Y PINES
// (Distribuir por WhatsApp individualmente ANTES de correr esto)
// ══════════════════════════════════════════════════
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

// ══════════════════════════════════════════════════
// CRIPTO
// ══════════════════════════════════════════════════
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

// ══════════════════════════════════════════════════
// SORTEO — Fisher-Yates con validación de no auto-asignación
// ══════════════════════════════════════════════════
function sortear(participantes) {
  const nombres = participantes.map(p => p.nombre);

  // Reintentar hasta 1000 veces para evitar bucle infinito
  for (let intento = 0; intento < 1000; intento++) {
    const mezclado = [...nombres];

    // Fisher-Yates
    for (let i = mezclado.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [mezclado[i], mezclado[j]] = [mezclado[j], mezclado[i]];
    }

    // Verificar que nadie se autoasignó
    const valido = mezclado.every((dest, i) => dest !== nombres[i]);
    if (valido) return mezclado;
  }

  throw new Error('No se pudo generar un sorteo válido después de 1000 intentos');
}

// ══════════════════════════════════════════════════
// SUPABASE
// ══════════════════════════════════════════════════
async function sbFetch(path, options = {}) {
  const url = `${SB_URL}/rest/v1/${path}`;
  const res = await fetch(url, {
    ...options,
    headers: {
      'apikey': SB_KEY,
      'Authorization': `Bearer ${SB_KEY}`,
      'Content-Type': 'application/json',
      'Prefer': 'return=representation',
      ...options.headers,
    },
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`Supabase error ${res.status}: ${text}`);
  return text ? JSON.parse(text) : null;
}

// ══════════════════════════════════════════════════
// MAIN
// ══════════════════════════════════════════════════
async function main() {
  console.log('🎄 Amigo Secreto 2026 — Setup y Sorteo\n');

  // 1. Verificar que la tabla no tiene sorteo previo
  console.log('📋 Verificando estado actual...');
  try {
    const rows = await sbFetch(`${TABLE}?select=id,destinatario_enc`);
    const conSorteo = rows?.filter(r => r.destinatario_enc);
    if (conSorteo?.length > 0) {
      console.log(`⚠️  Ya existen ${conSorteo.length} asignaciones en la tabla.`);
      console.log('   Para reiniciar: UPDATE amigo_secreto_2026 SET destinatario_enc = NULL, visto = FALSE;');
      console.log('   Abortando para no sobreescribir un sorteo existente.\n');
      process.exit(1);
    }
  } catch (e) {
    // Tabla no existe aún, continuar
    console.log('   (tabla vacía o nueva, continuando)\n');
  }

  // 2. Realizar el sorteo
  console.log('🎲 Realizando sorteo...');
  const asignados = sortear(PARTICIPANTES);

  console.log('\n📝 Asignaciones (SOLO para el organizador, NO compartir):');
  PARTICIPANTES.forEach((p, i) => {
    console.log(`   ${p.nombre.padEnd(12)} → ${asignados[i]}`);
  });
  console.log();

  // 3. Generar hashes y cifrar asignaciones
  console.log('🔐 Cifrando asignaciones...');
  const rows = [];
  for (let i = 0; i < PARTICIPANTES.length; i++) {
    const p = PARTICIPANTES[i];
    const pinHash = await sha256(p.pin);
    const destinatarioEnc = await cifrar(asignados[i], p.pin);
    rows.push({
      id:               p.id,
      nombre:           p.nombre,
      pin_hash:         pinHash,
      destinatario_enc: destinatarioEnc,
      visto:            false,
    });
    console.log(`   ✓ ${p.nombre}`);
  }
  console.log();

  // 4. Subir a Supabase (upsert)
  console.log('☁️  Subiendo a Supabase...');
  await sbFetch(`${TABLE}?on_conflict=id`, {
    method: 'POST',
    headers: { 'Prefer': 'resolution=merge-duplicates,return=representation' },
    body: JSON.stringify(rows),
  });

  console.log('\n✅ ¡Sorteo completado y subido exitosamente!');
  console.log('\n📱 Recuerda distribuir los PINs por WhatsApp INDIVIDUALMENTE:');
  PARTICIPANTES.forEach(p => {
    console.log(`   ${p.nombre}: PIN ${p.pin}`);
  });
  console.log('\n🌐 App disponible en: https://amigosecreto.claunet.cl');
}

main().catch(err => {
  console.error('\n❌ Error:', err.message);
  process.exit(1);
});
