import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { argon2Sync, createCipheriv, createDecipheriv, createHash, createHmac, createPublicKey, hkdfSync, verify } from 'node:crypto'

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

const ed25519Public = (raw) => createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), raw]), format: 'der', type: 'spki' })

test('registration proof and challenge signature verify', () => {
  const pub = ed25519Public(b64(auth.signPub))
  assert.equal(auth.registrationMessage, `ostia-server/register/v1\n${auth.signPub}\n${auth.boxPub}`)
  assert.ok(verify(null, Buffer.from(auth.registrationMessage), pub, b64(auth.registrationProof)))
  assert.equal(auth.challengeMessage, `ostia-server/auth/v1\n${auth.deviceId}\n${auth.nonce}`)
  assert.ok(verify(null, Buffer.from(auth.challengeMessage), pub, b64(auth.challengeSignature)))
  assert.ok(!verify(null, Buffer.from(`${auth.challengeMessage}x`), pub, b64(auth.challengeSignature)))
})

test('signed wrap read and manifest push bind slot, version and body', () => {
  const pub = ed25519Public(b64(auth.signPub))
  const ok = (message, signature) => verify(null, Buffer.from(message), pub, b64(signature))
  assert.equal(auth.wrapReadMessage, `ostia-server/wrap-read/v1\n${auth.deviceId}\n${auth.timestamp}\n${auth.wrapSlot}`)
  assert.ok(ok(auth.wrapReadMessage, auth.wrapReadSignature))
  assert.ok(!ok(auth.wrapReadMessage.replace(auth.wrapSlot, 'recovery'), auth.wrapReadSignature))
  const bodyHash = createHash('sha256').update(auth.manifestBody).digest('base64url')
  assert.equal(auth.manifestBodyHash, bodyHash)
  assert.equal(auth.manifestPutMessage, `ostia-server/manifest-put/v1\n${auth.deviceId}\n${auth.timestamp}\n${auth.ifMatch}\n${bodyHash}`)
  assert.ok(ok(auth.manifestPutMessage, auth.manifestPutSignature))
  const otherBody = createHash('sha256').update(`${auth.manifestBody} `).digest('base64url')
  assert.ok(!ok(auth.manifestPutMessage.replace(bodyHash, otherBody), auth.manifestPutSignature))
  assert.ok(!ok(auth.manifestPutMessage.replace(`\n${auth.ifMatch}\n`, `\n${auth.ifMatch + 1}\n`), auth.manifestPutSignature))
  assert.ok(!ok(auth.manifestPutMessage, auth.wrapReadSignature))
  assert.ok(!ok(auth.wrapReadMessage, auth.manifestPutSignature))
})

test('signed garbage collection and key replacement bind the version and body', () => {
  const pub = ed25519Public(b64(auth.signPub))
  const ok = (message, signature) => verify(null, Buffer.from(message), pub, b64(signature))
  const gcHash = createHash('sha256').update(auth.syncGcBody).digest('base64url')
  assert.equal(auth.syncGcBodyHash, gcHash)
  assert.equal(auth.syncGcMessage, `ostia-server/sync-gc/v1\n${auth.deviceId}\n${auth.timestamp}\n${auth.ifMatch}\n${gcHash}`)
  assert.ok(ok(auth.syncGcMessage, auth.syncGcSignature))
  const otherBody = createHash('sha256').update('{"keep":[]}').digest('base64url')
  assert.ok(!ok(auth.syncGcMessage.replace(gcHash, otherBody), auth.syncGcSignature))
  assert.ok(!ok(auth.syncGcMessage.replace(`\n${auth.ifMatch}\n`, `\n${auth.ifMatch + 1}\n`), auth.syncGcSignature))
  const rotateHash = createHash('sha256').update(auth.syncRotateBody).digest('base64url')
  assert.equal(auth.syncRotateBodyHash, rotateHash)
  assert.equal(auth.syncRotateMessage, `ostia-server/sync-rotate/v1\n${auth.deviceId}\n${auth.timestamp}\n${auth.ifMatch}\n${rotateHash}`)
  assert.ok(ok(auth.syncRotateMessage, auth.syncRotateSignature))
  assert.ok(!ok(auth.syncRotateMessage.replace(rotateHash, otherBody), auth.syncRotateSignature))
  assert.ok(!ok(auth.syncRotateMessage.replace(`\n${auth.ifMatch}\n`, `\n${auth.ifMatch + 1}\n`), auth.syncRotateSignature))
  for (const [message, signature] of [
    [auth.syncGcMessage, auth.manifestPutSignature],
    [auth.manifestPutMessage, auth.syncGcSignature],
    [auth.syncRotateMessage, auth.manifestPutSignature],
    [auth.manifestPutMessage, auth.syncRotateSignature],
    [auth.syncRotateMessage, auth.syncGcSignature],
  ]) {
    assert.ok(!ok(message, signature))
  }
})
