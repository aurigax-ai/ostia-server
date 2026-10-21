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

const ARTIFACT_POLICY = "connect-src 'none'; form-action 'none'; base-uri 'none'"
const MAX_LINK_LENGTH = 2048

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
  artifactFrame = frame
  root.replaceChildren(frame)
}

let artifactFrame = null
let linkConfirm = null

function parseLink(value) {
  if (typeof value !== 'string' || value.length > MAX_LINK_LENGTH) return null
  let url
  try {
    url = new URL(value)
  } catch {
    return null
  }
  if ((url.protocol !== 'http:' && url.protocol !== 'https:') || url.username || url.password) return null
  return url
}

function confirmLink(url) {
  linkConfirm?.remove()
  const open = element('button', { type: 'button' }, 'Open')
  const cancel = element('button', { type: 'button' }, 'Cancel')
  const box = element('div', { class: 'confirm', role: 'alertdialog', 'aria-label': 'Leaving the shared page' })
  box.append(element('span', {}, `This link leaves the shared page: ${url.host}`), open, cancel)
  const close = () => {
    box.remove()
    linkConfirm = null
  }
  open.addEventListener('click', () => {
    window.open(url.href, '_blank', 'noopener,noreferrer')
    close()
  })
  cancel.addEventListener('click', close)
  linkConfirm = box
  root.before(box)
  cancel.focus()
}

window.addEventListener('message', (event) => {
  if (!artifactFrame || event.source !== artifactFrame.contentWindow) return
  const url = parseLink(event.data?.ostiaOpen)
  if (url) confirmLink(url)
})

let warning = true

function acknowledged() {
  try {
    return localStorage.getItem(`ostia-notice:${shareId}`) === '1'
  } catch {
    return false
  }
}

function acknowledge() {
  try {
    localStorage.setItem(`ostia-notice:${shareId}`, '1')
  } catch {}
}

function renderWithNotice(html) {
  if (!warning || acknowledged()) {
    renderDocument(html)
    return
  }
  const show = element('button', { type: 'button' }, 'Show the page')
  show.addEventListener('click', () => {
    acknowledge()
    renderDocument(html)
  })
  const notice = element('div', { class: 'notice' })
  notice.append(
    element('p', {}, 'This page was published by an Ostia user. Do not enter passwords or personal details.'),
    show,
  )
  root.replaceChildren(notice)
  show.focus()
}

function renderBar() {
  const bar = element('div', { class: 'bar', role: 'region', 'aria-label': 'Share notice' })
  const open = element('button', { type: 'button', class: 'link' }, 'Report')
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
    reporting.replaceChildren(select, send, status)
  })
  const reporting = element('span', { class: 'reporting' })
  reporting.append(open)
  bar.append(element('span', {}, 'Shared from Ostia · made by a user, not by Ostia ·'), reporting)
  return bar
}

async function showPublic() {
  const blob = await fetchBlob()
  if (!blob) return
  renderWithNotice(new TextDecoder().decode(blob))
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
    renderWithNotice(await decryptBlob({ blob, id: shareId, key }))
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
      renderWithNotice(await decryptBlob({ blob, id: shareId, key }))
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
  warning = meta.warning !== false
  if (warning) document.body.prepend(renderBar())
  if (meta.mode === 'public') await showPublic()
  else if (meta.mode === 'link') await showLink()
  else if (meta.mode === 'password') showPasswordForm(meta)
  else showMessage('This share uses an unsupported format.')
}
