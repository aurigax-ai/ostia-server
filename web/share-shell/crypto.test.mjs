import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { decryptBlob, deriveKey, fragmentKey, fromBase64Url, toBase64Url } from './crypto.js'

const vectors = JSON.parse(readFileSync(new URL('../../testdata/vectors/share.json', import.meta.url), 'utf8'))

for (const vector of vectors.cases) {
  test(`share vector ${vector.name}`, async () => {
    const fragment = vector.fragmentKey ? fromBase64Url(vector.fragmentKey) : null
    const key = await deriveKey({
      mode: vector.mode,
      password: vector.password,
      salt: vector.salt ? fromBase64Url(vector.salt) : undefined,
      fragment,
    })
    assert.equal(toBase64Url(key), vector.derivedKey)
    const html = await decryptBlob({ blob: fromBase64Url(vector.blob), id: vector.id, key })
    assert.equal(html, vector.plaintext)
  })

  test(`share vector ${vector.name} is bound to its id`, async () => {
    const fragment = vector.fragmentKey ? fromBase64Url(vector.fragmentKey) : null
    const key = await deriveKey({ mode: vector.mode, password: vector.password, salt: vector.salt ? fromBase64Url(vector.salt) : undefined, fragment })
    await assert.rejects(decryptBlob({ blob: fromBase64Url(vector.blob), id: 'someotherid', key }))
  })
}

test('fragmentKey reads k and rejects wrong lengths', () => {
  const good = toBase64Url(new Uint8Array(32).fill(7))
  assert.equal(fragmentKey(`#k=${good}`)?.length, 32)
  assert.equal(fragmentKey(`k=${good}`)?.length, 32)
  assert.equal(fragmentKey('#k=AAAA'), null)
  assert.equal(fragmentKey(''), null)
})

test('tampered ciphertext is refused', async () => {
  const vector = vectors.cases[0]
  const blob = fromBase64Url(vector.blob)
  blob[blob.length - 1] ^= 1
  const key = await deriveKey({ mode: vector.mode, password: vector.password, salt: vector.salt ? fromBase64Url(vector.salt) : undefined, fragment: vector.fragmentKey ? fromBase64Url(vector.fragmentKey) : null })
  await assert.rejects(decryptBlob({ blob, id: vector.id, key }))
})

test('unknown format version is refused', async () => {
  await assert.rejects(decryptBlob({ blob: new Uint8Array(64).fill(9), id: 'x', key: new Uint8Array(32) }), /unsupported share format/)
})
