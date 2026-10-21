import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import {
  argon2Sync,
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  hkdfSync,
  verify,
} from 'node:crypto'

const read = (name) => JSON.parse(readFileSync(new URL(name, import.meta.url), 'utf8'))
const sync = read('sync.json')
const auth = read('auth.json')

const b64 = (text) => Buffer.from(text, 'base64url')
const toB64 = (bytes) => Buffer.from(bytes).toString('base64url')

const subkey = (profileKey, label) => Buffer.from(hkdfSync('sha256', profileKey, Buffer.alloc(0), label, 32))

function sealWithNonce(key, plaintext, aad, nonce) {
  const cipher = createCipheriv('aes-256-gcm', key, nonce)
  cipher.setAAD(aad)
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()])
  return Buffer.concat([nonce, body, cipher.getAuthTag()])
}

function open(key, sealed, aad) {
  const nonce = sealed.subarray(0, 12)
  const tag = sealed.subarray(sealed.length - 16)
  const body = sealed.subarray(12, sealed.length - 16)
  const decipher = createDecipheriv('aes-256-gcm', key, nonce)
  decipher.setAAD(aad)
  decipher.setAuthTag(tag)
  return Buffer.concat([decipher.update(body), decipher.final()])
}

const profileKey = b64(sync.profileKey)

test('content hash and blob id', () => {
  const content = Buffer.from(sync.content)
  const hash = createHash('sha256').update(content).digest()
  assert.equal(toB64(hash), sync.contentHash)
  const mac = createHmac('sha256', subkey(profileKey, 'ostia-sync/path'))
  mac.update(Buffer.concat([Buffer.from(sync.path), Buffer.from([0]), hash]))
  assert.equal(toB64(mac.digest()), sync.blobId)
})

test('sealed blob matches and opens', () => {
  const key = subkey(profileKey, 'ostia-sync/blob')
  const aad = Buffer.from(`ostia-sync/blob/v1\n${sync.path}`)
  assert.equal(toB64(sealWithNonce(key, Buffer.from(sync.content), aad, b64(sync.blobNonce))), sync.sealedBlob)
  assert.equal(open(key, b64(sync.sealedBlob), aad).toString(), sync.content)
})

test('sealed manifest matches and opens', () => {
  const key = subkey(profileKey, 'ostia-sync/manifest')
  const aad = Buffer.from('ostia-sync/manifest/v1')
  assert.equal(toB64(sealWithNonce(key, Buffer.from(sync.manifest), aad, b64(sync.manifestNonce))), sync.sealedManifest)
  assert.equal(open(key, b64(sync.sealedManifest), aad).toString(), sync.manifest)
})

test('passphrase wrap matches and opens', () => {
  const wrap = b64(sync.passphraseWrap)
  const header = wrap.subarray(0, 23)
  assert.equal(header[0], 1)
  assert.equal(header.readUInt32BE(1), sync.argon.memoryKiB)
  assert.equal(header[5], sync.argon.passes)
  assert.equal(header[6], sync.argon.lanes)
  const salt = header.subarray(7)
  const key = Buffer.from(
    argon2Sync('argon2id', {
      message: Buffer.from(sync.passphrase),
      nonce: salt,
      parallelism: sync.argon.lanes,
      tagLength: 32,
      memory: sync.argon.memoryKiB,
      passes: sync.argon.passes,
    }),
  )
  const aad = Buffer.concat([Buffer.from('ostia-sync/wrap/passphrase/v1'), header])
  assert.deepEqual(open(key, wrap.subarray(23), aad), profileKey)
  assert.equal(toB64(sealWithNonce(key, profileKey, aad, b64(sync.wrapNonce))), toB64(wrap.subarray(23)))
})

const x25519Private = (raw) => createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), raw]), format: 'der', type: 'pkcs8' })
const x25519Public = (raw) => createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), raw]), format: 'der', type: 'spki' })

const ed25519Public = (raw) => createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), raw]), format: 'der', type: 'spki' })

function splitDeviceWrap(wrap) {
  assert.equal(wrap[0], 2)
  const idLen = wrap[1]
  const counterAt = 2 + idLen
  const headerLen = counterAt + 8 + 32 + 12
  const sigAt = wrap.length - 64
  return {
    signerId: wrap.subarray(2, counterAt).toString(),
    counter: wrap.readBigUInt64BE(counterAt),
    ephemeral: wrap.subarray(counterAt + 8, counterAt + 40),
    header: wrap.subarray(0, headerLen),
    sealed: wrap.subarray(headerLen - 12, sigAt),
    signed: wrap.subarray(0, sigAt),
    signature: wrap.subarray(sigAt),
  }
}

const wrapSignatureMessage = (slot, signed) => Buffer.concat([Buffer.from(sync.wrapSignatureContext), Buffer.from(`${slot}\n`), signed])
const signerPub = ed25519Public(b64(sync.wrapSignerSignPub))

test('device wrap v2 opens with the device key, matches with the fixed ephemeral key and verifies', () => {
  const parts = splitDeviceWrap(b64(sync.deviceWrap))
  assert.equal(parts.signerId, sync.wrapSignerId)
  assert.equal(parts.counter, BigInt(sync.wrapCounter))
  const devicePub = b64(sync.deviceBoxPublicKey)
  const deriveKey = (shared) =>
    Buffer.from(hkdfSync('sha256', shared, Buffer.alloc(0), Buffer.concat([Buffer.from('ostia-sync/wrap/device'), parts.ephemeral, devicePub]), 32))
  const aad = Buffer.concat([parts.header, Buffer.from(sync.wrapSlot)])
  const shared = diffieHellman({ privateKey: x25519Private(b64(sync.deviceBoxPrivateKey)), publicKey: x25519Public(parts.ephemeral) })
  assert.deepEqual(open(deriveKey(shared), parts.sealed, aad), profileKey)

  const ephemeralShared = diffieHellman({ privateKey: x25519Private(b64(sync.ephemeralPrivateKey)), publicKey: x25519Public(devicePub) })
  assert.equal(toB64(sealWithNonce(deriveKey(ephemeralShared), profileKey, aad, b64(sync.deviceWrapNonce))), toB64(parts.sealed))

  assert.ok(verify(null, wrapSignatureMessage(sync.wrapSlot, parts.signed), signerPub, parts.signature))
  assert.ok(!verify(null, wrapSignatureMessage('device:other', parts.signed), signerPub, parts.signature))
})

test('forged and tampered device wraps fail the signature', () => {
  for (const blob of [sync.wrongKeySignedWrap, sync.tamperedWrap]) {
    const parts = splitDeviceWrap(b64(blob))
    assert.ok(!verify(null, wrapSignatureMessage(sync.wrapSlot, parts.signed), signerPub, parts.signature))
  }
})

test('registration proof and challenge signature verify', () => {
  const pub = ed25519Public(b64(auth.signPub))
  assert.equal(auth.registrationMessage, `ostia-server/register/v1\n${auth.signPub}\n${auth.boxPub}`)
  assert.ok(verify(null, Buffer.from(auth.registrationMessage), pub, b64(auth.registrationProof)))
  assert.equal(auth.challengeMessage, `ostia-server/auth/v1\n${auth.deviceId}\n${auth.nonce}`)
  assert.ok(verify(null, Buffer.from(auth.challengeMessage), pub, b64(auth.challengeSignature)))
  assert.ok(!verify(null, Buffer.from(`${auth.challengeMessage}x`), pub, b64(auth.challengeSignature)))
})
