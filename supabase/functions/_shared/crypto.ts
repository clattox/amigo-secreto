// Utilidades criptográficas compartidas entre Edge Functions

/** Genera un código alfanumérico sin caracteres ambiguos (0,O,I,l,1) */
export function generateCode(length = 6): string {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const arr = new Uint8Array(length);
  crypto.getRandomValues(arr);
  return Array.from(arr).map((b) => chars[b % chars.length]).join("");
}

/** Genera un PIN de 4 dígitos (con ceros a la izquierda) */
export function generatePin(): string {
  const arr = new Uint32Array(1);
  crypto.getRandomValues(arr);
  return String(arr[0] % 10000).padStart(4, "0");
}

/** Genera un salt aleatorio como hex */
export function generateSalt(): string {
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** PBKDF2-SHA256: deriva hash de un PIN+salt */
export async function pbkdf2Hash(
  pin: string,
  saltHex: string,
  iterations = 200_000
): Promise<string> {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(pin),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const salt = hexToBytes(saltHex);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    keyMaterial,
    256
  );
  return bytesToHex(new Uint8Array(bits));
}

/** SHA-256 simple (para hashear IPs) */
export async function sha256(input: string): Promise<string> {
  const enc = new TextEncoder();
  const hash = await crypto.subtle.digest("SHA-256", enc.encode(input));
  return bytesToHex(new Uint8Array(hash));
}

/** Deriva clave AES-GCM desde PIN + salt + serverSecret */
export async function deriveAesKey(
  pin: string,
  saltHex: string,
  serverSecret: string
): Promise<CryptoKey> {
  const combined = pin + "|" + serverSecret;
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(combined),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt: hexToBytes(saltHex), iterations: 150_000 },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/** Cifra texto con AES-GCM, retorna { encrypted, iv } en hex */
export async function aesEncrypt(
  plaintext: string,
  key: CryptoKey
): Promise<{ encrypted: string; iv: string }> {
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const enc = new TextEncoder();
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    enc.encode(plaintext)
  );
  return {
    encrypted: bytesToHex(new Uint8Array(ciphertext)),
    iv: bytesToHex(iv),
  };
}

/** Descifra texto con AES-GCM */
export async function aesDecrypt(
  encryptedHex: string,
  ivHex: string,
  key: CryptoKey
): Promise<string> {
  const dec = new TextDecoder();
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: hexToBytes(ivHex) },
    key,
    hexToBytes(encryptedHex)
  );
  return dec.decode(plaintext);
}

// ── Helpers ──────────────────────────────────────────────
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Derangement de Fisher-Yates: sorteo sin auto-asignación */
export function generateDerangement(n: number): number[] {
  return generateDerangementWithExclusions(n, []);
}

/**
 * Derangement respetando exclusiones.
 * @param n - cantidad de participantes
 * @param exclusions - pares [a, b] de índices que NO pueden quedar juntos (ni a→b ni b→a)
 */
export function generateDerangementWithExclusions(
  n: number,
  exclusions: [number, number][]
): number[] {
  if (n < 2) throw new Error("Mínimo 2 participantes");

  // Construir set de pares inválidos (bidireccional)
  const forbidden = new Set<string>();
  for (const [a, b] of exclusions) {
    forbidden.add(`${a}-${b}`);
    forbidden.add(`${b}-${a}`);
  }

  const isValid = (perm: number[]) => {
    // No auto-asignación
    if (!perm.every((v, i) => v !== i)) return false;
    // No pares excluidos
    for (let i = 0; i < perm.length; i++) {
      if (forbidden.has(`${i}-${perm[i]}`)) return false;
    }
    return true;
  };

  let perm: number[] = [];
  let attempts = 0;

  do {
    perm = Array.from({ length: n }, (_, i) => i);
    // Fisher-Yates shuffle
    for (let i = n - 1; i > 0; i--) {
      const arr = new Uint32Array(1);
      crypto.getRandomValues(arr);
      const j = arr[0] % (i + 1);
      [perm[i], perm[j]] = [perm[j], perm[i]];
    }
    attempts++;
    if (attempts > 10_000) {
      throw new Error(
        "No se pudo generar un sorteo válido con las restricciones actuales. " +
        "Verifica que las exclusiones no sean demasiadas para el grupo."
      );
    }
  } while (!isValid(perm));

  return perm;
}

/** CORS headers estándar */
export const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
