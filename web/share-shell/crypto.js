export const FORMAT_VERSION = 1
export const NONCE_BYTES = 12
export const KEY_BYTES = 32
export const PBKDF2_ITERATIONS = 600000
const AAD_PREFIX = 'ostia-share/1:'
const COMBINE_INFO = 'ostia-share/1/key'

const encoder = new TextEncoder()

export function fromBase64Url(text) {
  const padded = text.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(text.length / 4) * 4, '=')
  const binary = atob(padded)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

export function toBase64Url(bytes) {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function fragmentKey(hash) {
  const params = new URLSearchParams(hash.startsWith('#') ? hash.slice(1) : hash)
  const text = params.get('k')
  if (!text) return null
  const key = fromBase64Url(text)
  return key.length === KEY_BYTES ? key : null
}

async function pbkdf2(password, salt) {
  const base = await crypto.subtle.importKey('raw', encoder.encode(password.normalize('NFKC')), 'PBKDF2', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PBKDF2_ITERATIONS }, base, KEY_BYTES * 8)
  return new Uint8Array(bits)
}

async function hkdf(material) {
  const base = await crypto.subtle.importKey('raw', material, 'HKDF', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: encoder.encode(COMBINE_INFO) },
    base,
    KEY_BYTES * 8,
  )
  return new Uint8Array(bits)
}

export async function deriveKey({ mode, password, salt, fragment }) {
  if (mode === 'link') return fragment
  if (mode !== 'password') throw new Error('unsupported mode')
  const stretched = await pbkdf2(password, salt)
  if (!fragment) return stretched
  const material = new Uint8Array(stretched.length + fragment.length)
  material.set(stretched, 0)
  material.set(fragment, stretched.length)
  return hkdf(material)
}

export async function decryptBlob({ blob, id, key }) {
  if (blob.length < 1 + NONCE_BYTES + 16 || blob[0] !== FORMAT_VERSION) throw new Error('unsupported share format')
  const aesKey = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt'])
  const nonce = blob.subarray(1, 1 + NONCE_BYTES)
  const sealed = blob.subarray(1 + NONCE_BYTES)
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData: encoder.encode(AAD_PREFIX + id) }, aesKey, sealed)
  return new TextDecoder().decode(plain)
}
