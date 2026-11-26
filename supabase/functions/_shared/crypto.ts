// Shared crypto utilities for Amigo Secreto Edge Functions

export const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

export function generateCode(length = 6): string {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
  const bytes = crypto.getRandomValues(new Uint8Array(length))
  return Array.from(bytes).map(b => chars[b % chars.length]).join('')
}

export function generatePin(): string {
  const n = crypto.getRandomValues(new Uint8Array(1))[0] % 10000
  return n.toString().padStart(4, '0')
}

export function generateSalt(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

export async function pbkdf2Hash(pin: string, saltHex: string, iterations: number): Promise<string> {
  const enc = new TextEncoder()
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(pin), 'PBKDF2', false, ['deriveBits'])
  const salt = new Uint8Array(saltHex.match(/.{2}/g)!.map(h => parseInt(h, 16)))
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, keyMaterial, 256)
  return Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, '0')).join('')
}

export async function sha256(input: string): Promise<string> {
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input))
  return Array.from(new Uint8Array(bytes)).map(b => b.toString(16).padStart(2, '0')).join('')
}

export async function deriveAesKey(participantId: string, saltHex: string, serverSecret: string): Promise<CryptoKey> {
  const enc = new TextEncoder()
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(participantId + '|' + serverSecret), 'PBKDF2', false, ['deriveKey'])
  const salt = new Uint8Array(saltHex.match(/.{2}/g)!.map(h => parseInt(h, 16)))
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 150_000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  )
}

export async function aesEncrypt(plaintext: string, key: CryptoKey): Promise<{ encrypted: string; iv: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const enc = new TextEncoder()
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plaintext))
  return {
    encrypted: Array.from(new Uint8Array(encrypted)).map(b => b.toString(16).padStart(2, '0')).join(''),
    iv: Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join(''),
  }
}

export async function aesDecrypt(encryptedHex: string, ivHex: string, key: CryptoKey): Promise<string> {
  const encrypted = new Uint8Array(encryptedHex.match(/.{2}/g)!.map(h => parseInt(h, 16)))
  const iv = new Uint8Array(ivHex.match(/.{2}/g)!.map(h => parseInt(h, 16)))
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, encrypted)
  return new TextDecoder().decode(decrypted)
}

export function generateDerangement(n: number): number[] {
  const arr = Array.from({ length: n }, (_, i) => i)
  for (let i = n - 1; i > 0; i--) {
    const bytes = crypto.getRandomValues(new Uint8Array(4))
    const j = new DataView(bytes.buffer).getUint32(0) % (i + 1)
    ;[arr[i], arr[j]] = [arr[j], arr[i]]
  }
  // Verificar derangement (ninguno en su posición original)
  for (let i = 0; i < n; i++) {
    if (arr[i] === i) return generateDerangement(n)
  }
  return arr
}
