import { decryptBlob, deriveKey, fragmentKey, fromBase64Url } from './crypto.js'

const MESSAGES = {
  404: 'This share does not exist.',
  410: 'This share has expired or was removed.',
}
const REPORT_REASONS = [
  ['illegal', 'Illegal content'],
  ['malware', 'Malware or phishing'],
  ['abuse', 'Harassment or abuse'],
  ['other', 'Something else'],
]

const root = document.getElementById('root')
const shareId = location.hostname.split('.')[0]

function element(tag, attributes = {}, text = '') {
  const node = document.createElement(tag)
  for (const [name, value] of Object.entries(attributes)) node.setAttribute(name, value)
  if (text) node.textContent = text
  return node
}

function showMessage(text) {
  root.replaceChildren(element('p', { class: 'message', role: 'status' }, text))
}

async function fetchMeta() {
  const response = await fetch('/meta', { cache: 'no-store' })
  if (!response.ok) {
    showMessage(MESSAGES[response.status] ?? 'This share could not be loaded.')
    return null
  }
  return response.json()
}

async function fetchBlob() {
  const response = await fetch('/blob', { cache: 'no-store' })
  if (!response.ok) {
    showMessage(MESSAGES[response.status] ?? 'This share could not be loaded.')
    return null
  }
  return new Uint8Array(await response.arrayBuffer())
}

const ARTIFACT_POLICY = "connect-src 'none'"

function withArtifactPolicy(html) {
  const doc = new DOMParser().parseFromString(html, 'text/html')
  const policy = doc.createElement('meta')
  policy.httpEquiv = 'Content-Security-Policy'
  policy.content = ARTIFACT_POLICY
  doc.head.prepend(policy)
  const type = doc.doctype ? new XMLSerializer().serializeToString(doc.doctype) : ''
  return type + doc.documentElement.outerHTML
}

function renderDocument(html) {
  const frame = element('iframe', { sandbox: 'allow-scripts', title: 'Shared artifact', class: 'artifact' })
  frame.srcdoc = withArtifactPolicy(html)
  root.replaceChildren(frame, reportBar())
}

function reportBar() {
  const bar = element('div', { class: 'bar' })
  const open = element('button', { type: 'button', class: 'link' }, 'Report this share')
  open.addEventListener('click', () => {
    const select = element('select', { 'aria-label': 'Reason' })
    for (const [value, label] of REPORT_REASONS) select.append(element('option', { value }, label))
    const send = element('button', { type: 'button' }, 'Send report')
    const status = element('span', { role: 'status' })
    send.addEventListener('click', async () => {
      const response = await fetch('/report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: select.value }),
      })
      status.textContent = response.ok ? 'Thank you, the report was recorded.' : 'The report could not be sent.'
    })
    bar.replaceChildren(select, send, status)
  })
  bar.append(open)
  return bar
}

async function showLink() {
  const key = fragmentKey(location.hash)
  if (!key) {
    showMessage('This link is incomplete: the part after # is missing.')
    return
  }
  const blob = await fetchBlob()
  if (!blob) return
  try {
    renderDocument(await decryptBlob({ blob, id: shareId, key }))
  } catch {
    showMessage('This share could not be decrypted. The link may be damaged.')
  }
}

function showPasswordForm(meta) {
  const input = element('input', { type: 'password', autocomplete: 'off', 'aria-label': 'Password', required: '' })
  const submit = element('button', { type: 'submit' }, 'Open')
  const status = element('p', { class: 'message', role: 'status' })
  const form = element('form', { class: 'password' })
  form.append(input, submit, status)
  form.addEventListener('submit', async (event) => {
    event.preventDefault()
    submit.disabled = true
    status.textContent = 'Opening…'
    try {
      const blob = await fetchBlob()
      if (!blob) return
      const key = await deriveKey({
        mode: 'password',
        password: input.value,
        salt: fromBase64Url(meta.salt),
        fragment: fragmentKey(location.hash),
      })
      renderDocument(await decryptBlob({ blob, id: shareId, key }))
    } catch {
      status.textContent = 'Wrong password.'
      submit.disabled = false
    }
  })
  root.replaceChildren(form)
  input.focus()
}

const meta = await fetchMeta()
if (meta) {
  if (meta.mode === 'link') await showLink()
  else if (meta.mode === 'password') showPasswordForm(meta)
  else showMessage('This share uses an unsupported format.')
}
