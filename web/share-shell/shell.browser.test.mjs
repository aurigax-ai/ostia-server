import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { readFileSync } from 'node:fs'

const dir = new URL('./', import.meta.url)
const goSource = readFileSync(new URL('../../internal/publish/share.go', import.meta.url), 'utf8')
const shellCsp = goSource.match(/shellContentSecurityPolicy\s*=\s*"([^"]+)"/)[1]
const permissionsPolicy = goSource.match(/permissionsPolicy\s*=\s*"([^"]+)"/)[1]

async function loadPlaywright() {
  try {
    return await import(process.env.PLAYWRIGHT_CORE ?? 'playwright-core')
  } catch {
    return null
  }
}

const playwright = process.env.CHROME_PATH ? await loadPlaywright() : null
const skip = playwright ? false : 'set CHROME_PATH and make playwright-core importable (or PLAYWRIGHT_CORE) to run browser tests'

const EVIL = 'http://evil.localhost'
const artifacts = {
  loc: (evil) => `<p>stay</p><script>setTimeout(() => { location.href = '${evil}/loc' }, 50)</script>`,
  refresh: (evil) => `<meta http-equiv="refresh" content="0;url=${evil}/refresh"><p>stay</p>`,
  top: (evil) => `<p>stay</p><a id="a" target="_top" href="${evil}/top">x</a><script>setTimeout(() => document.getElementById('a').click(), 50)</script>`,
  open: (evil) => `<p>stay</p><script>setTimeout(() => window.open('${evil}/open', '_blank'), 50)</script>`,
  form: (evil) => `<p>stay</p><form id="f" method="post" action="${evil}/form"><input name="a"></form><script>setTimeout(() => document.getElementById('f').submit(), 50)</script>`,
  first: () => `<script>parent.postMessage({ ostiaOpen: 'http://first.localhost/' }, '*'); setTimeout(() => parent.postMessage({ ostiaOpen: 'http://second.localhost/' }, '*'), 300)</script><p>stay</p>`,
  bad: () => `<p>stay</p><script>for (const u of ['javascript:alert(1)', 'data:text/html,x', 'ftp://x/', 'http://u:p@x.localhost/', 'http://x.localhost/' + 'a'.repeat(2100)]) parent.postMessage({ ostiaOpen: u }, '*')</script>`,
  long: () => `<p>stay</p><script>parent.postMessage({ ostiaOpen: 'https://accounts.google.com.secure-login.verification.example.org/x' }, '*')</script>`,
  early: (evil) => `<script>parent.postMessage({ ostiaOpen: '${evil}/ok' }, '*')</script><p>stay</p>`,
  head: () => `<script>window.headFirst = document.head.firstElementChild.outerHTML</script><p>stay</p>`,
}

let server, evilServer, browser, base, evilHits, views
const evilPort = () => evilServer.address().port

before(async () => {
  if (skip) return
  evilHits = []
  views = 0
  evilServer = createServer((req, res) => {
    evilHits.push(req.url)
    res.end('ok')
  })
  await new Promise((resolve) => evilServer.listen(0, '127.0.0.1', resolve))
  server = createServer((req, res) => {
    const id = req.headers.host.split('.')[0]
    const path = req.url.split('?')[0]
    const headers = {}
    let body
    let type = 'text/plain'
    if (path === '/meta') {
      type = 'application/json'
      body = JSON.stringify({ v: 1, mode: 'public', size: 1, salt: '', expiresAt: 0, warning: true })
    } else if (path === '/blob') {
      type = 'application/octet-stream'
      body = `<!doctype html><body>${artifacts[id](`${EVIL}:${evilPort()}`)}`
    } else if (path === '/view') {
      views++
      res.writeHead(204).end()
      return
    } else if (path === '/') {
      type = 'text/html'
      body = readFileSync(new URL('index.html', dir))
      headers['Content-Security-Policy'] = shellCsp
      headers['Permissions-Policy'] = permissionsPolicy
    } else if (['/shell.js', '/crypto.js', '/shell.css'].includes(path)) {
      type = path.endsWith('.css') ? 'text/css' : 'text/javascript'
      body = readFileSync(new URL(`.${path}`, dir))
    } else {
      res.writeHead(404).end()
      return
    }
    res.writeHead(200, { 'Content-Type': type, ...headers }).end(body)
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  base = server.address().port
  browser = await playwright.chromium.launch({ executablePath: process.env.CHROME_PATH })
})

after(async () => {
  await browser?.close()
  server?.close()
  evilServer?.close()
})

async function openShare(id, { accept = true } = {}) {
  const context = await browser.newContext()
  const page = await context.newPage()
  const url = `http://${id}.localhost:${base}/`
  await page.goto(url)
  if (accept) await page.getByRole('button', { name: 'Show the page' }).click()
  return { context, page, url }
}

for (const id of ['loc', 'refresh', 'top', 'open', 'form']) {
  test(`frame-src none keeps a frame that tries ${id} on the share`, { skip }, async () => {
    evilHits.length = 0
    const { context, page, url } = await openShare(id)
    await page.waitForTimeout(1000)
    assert.equal(page.url(), url)
    assert.equal(context.pages().length, 1)
    assert.deepEqual(evilHits, [])
    await context.close()
  })
}

test('the frame is not created, and no view counted, before the notice is accepted', { skip }, async () => {
  views = 0
  const { context, page } = await openShare('head', { accept: false })
  await page.waitForTimeout(300)
  assert.equal(await page.locator('iframe').count(), 0)
  assert.equal(views, 0)
  await page.getByRole('button', { name: 'Show the page' }).click()
  await page.locator('iframe').waitFor()
  await page.waitForTimeout(200)
  assert.equal(views, 1)
  await context.close()
})

test('the policy meta is the first element of the artifact head', { skip }, async () => {
  const { context, page } = await openShare('head')
  const frame = page.frames().find((f) => f !== page.mainFrame()) ?? (await (await page.locator('iframe').elementHandle()).contentFrame())
  await frame.getByText('stay').waitFor()
  const first = await frame.evaluate(() => window.headFirst)
  assert.match(first, /^<meta http-equiv="Content-Security-Policy" content="connect-src 'none'; form-action 'none'; base-uri 'none'">$/)
  await context.close()
})

test('Open needs a click and cannot be clicked in the first second', { skip }, async () => {
  evilHits.length = 0
  const { context, page } = await openShare('early')
  const confirm = page.getByRole('alertdialog')
  await confirm.waitFor()
  const frameBefore = await page.locator('iframe').boundingBox()
  const open = confirm.getByRole('button', { name: 'Open' })
  assert.equal(await open.isDisabled(), true)
  const box = await open.boundingBox()
  const popups = []
  context.on('page', (p) => popups.push(p))
  assert.deepEqual(evilHits, [])
  await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2)
  await page.waitForTimeout(300)
  assert.equal(popups.length, 0)
  assert.equal(await confirm.count(), 1)
  assert.deepEqual(await page.locator('iframe').boundingBox(), frameBefore)
  await page.waitForTimeout(1500)
  assert.equal(popups.length, 0, 'a message alone must not open anything')
  assert.equal(await open.isDisabled(), false)
  const popup = page.waitForEvent('popup')
  await open.click()
  await (await popup).waitForLoadState()
  assert.deepEqual(evilHits, ['/ok'])
  await context.close()
})

test('a second message does not replace the host being shown', { skip }, async () => {
  const { context, page } = await openShare('first')
  const confirm = page.getByRole('alertdialog')
  await confirm.waitFor()
  await page.waitForTimeout(800)
  assert.match(await confirm.innerText(), /first\.localhost/)
  assert.doesNotMatch(await confirm.innerText(), /second/)
  await context.close()
})

test('links with a bad scheme, credentials or length show no confirm', { skip }, async () => {
  const { context, page } = await openShare('bad')
  await page.waitForTimeout(800)
  assert.equal(await page.getByRole('alertdialog').count(), 0)
  await context.close()
})

test('the confirm shows the registrable domain and cuts a long subdomain in the middle', { skip }, async () => {
  const { context, page } = await openShare('long')
  const confirm = page.getByRole('alertdialog')
  await confirm.waitFor()
  assert.equal(await confirm.locator('strong').innerText(), 'example.org')
  const shown = await confirm.locator('.host').innerText()
  assert.match(shown, /…/)
  assert.ok(shown.endsWith('example.org'))
  assert.equal(await confirm.locator('.host').getAttribute('title'), 'accounts.google.com.secure-login.verification.example.org')
  await context.close()
})
