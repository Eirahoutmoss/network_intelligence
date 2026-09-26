// Regenerates nexus.ico and the installer bitmaps from nexus.svg.
//   cd tests/e2e && node ../../deployments/windows/assets/generate.mjs
// Uses the Playwright Chromium already used for end-to-end tests.
import { readFileSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

// Resolve Playwright from the current directory (tests/e2e).
const { chromium } = createRequire(join(process.cwd(), 'noop.js'))('@playwright/test')
const here = dirname(fileURLToPath(import.meta.url))
const svg = readFileSync(join(here, 'nexus.svg'), 'utf8')
const browser = await chromium.launch(process.env.PW_CHROMIUM ? { executablePath: process.env.PW_CHROMIUM } : {})
const page = await browser.newPage()
await page.setContent('<canvas id="c"></canvas>')

// draw renders HTML/SVG markup into a w×h canvas and returns RGBA pixels (+ PNG).
async function draw(w, h, markup) {
  return page.evaluate(async ({ w, h, markup }) => {
    const img = new Image()
    img.src = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(markup)
    await img.decode()
    const c = document.getElementById('c')
    c.width = w
    c.height = h
    const ctx = c.getContext('2d')
    ctx.clearRect(0, 0, w, h)
    ctx.drawImage(img, 0, 0, w, h)
    return { rgba: Array.from(ctx.getImageData(0, 0, w, h).data), png: c.toDataURL('image/png').split(',')[1] }
  }, { w, h, markup })
}

// ICO: 32-bit DIB entries for small sizes, PNG for 256 px.
const sizes = [16, 20, 24, 32, 40, 48, 64, 128, 256]
const images = []
for (const s of sizes) {
  const { rgba, png } = await draw(s, s, svg)
  if (s >= 256) {
    images.push({ s, data: Buffer.from(png, 'base64') })
    continue
  }
  const header = Buffer.alloc(40)
  header.writeUInt32LE(40, 0)
  header.writeInt32LE(s, 4)
  header.writeInt32LE(s * 2, 8) // XOR + AND masks
  header.writeUInt16LE(1, 12)
  header.writeUInt16LE(32, 14)
  const xor = Buffer.alloc(s * s * 4)
  for (let y = 0; y < s; y++) {
    for (let x = 0; x < s; x++) {
      const src = ((s - 1 - y) * s + x) * 4 // bottom-up
      const dst = (y * s + x) * 4
      xor[dst] = rgba[src + 2]
      xor[dst + 1] = rgba[src + 1]
      xor[dst + 2] = rgba[src]
      xor[dst + 3] = rgba[src + 3]
    }
  }
  const andRow = Math.ceil(s / 32) * 4
  images.push({ s, data: Buffer.concat([header, xor, Buffer.alloc(andRow * s)]) })
}
const dir = Buffer.alloc(6 + 16 * images.length)
dir.writeUInt16LE(0, 0)
dir.writeUInt16LE(1, 2)
dir.writeUInt16LE(images.length, 4)
let offset = dir.length
images.forEach((im, i) => {
  const e = 6 + i * 16
  dir.writeUInt8(im.s >= 256 ? 0 : im.s, e)
  dir.writeUInt8(im.s >= 256 ? 0 : im.s, e + 1)
  dir.writeUInt16LE(1, e + 4)
  dir.writeUInt16LE(32, e + 6)
  dir.writeUInt32LE(im.data.length, e + 8)
  dir.writeUInt32LE(offset, e + 12)
  offset += im.data.length
})
writeFileSync(join(here, 'nexus.ico'), Buffer.concat([dir, ...images.map((i) => i.data)]))

// 24-bit BMP for the installer pages.
function bmp(w, h, rgba) {
  const row = Math.ceil((w * 3) / 4) * 4
  const buf = Buffer.alloc(54 + row * h)
  buf.write('BM', 0)
  buf.writeUInt32LE(buf.length, 2)
  buf.writeUInt32LE(54, 10)
  buf.writeUInt32LE(40, 14)
  buf.writeInt32LE(w, 18)
  buf.writeInt32LE(h, 22)
  buf.writeUInt16LE(1, 26)
  buf.writeUInt16LE(24, 28)
  buf.writeUInt32LE(row * h, 34)
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const src = ((h - 1 - y) * w + x) * 4
      const dst = 54 + y * row + x * 3
      buf[dst] = rgba[src + 2]
      buf[dst + 1] = rgba[src + 1]
      buf[dst + 2] = rgba[src]
    }
  }
  return buf
}
const logo = svg.replace('<svg ', '<svg x="{X}" y="{Y}" width="{S}" height="{S}" ')
const place = (x, y, s) => logo.replace('{X}', x).replace('{Y}', y).replaceAll('{S}', s)
const welcome = `<svg xmlns="http://www.w3.org/2000/svg" width="164" height="314">
  <defs><linearGradient id="g" x1="0" y1="0" x2="0.6" y2="1"><stop offset="0" stop-color="#0f172a"/><stop offset="0.55" stop-color="#1e293b"/><stop offset="1" stop-color="#134e4a"/></linearGradient></defs>
  <rect width="164" height="314" fill="url(#g)"/>
  <g stroke="#14b8a6" stroke-opacity="0.18" stroke-width="1.2" fill="none">
    <circle cx="30" cy="250" r="5"/><circle cx="95" cy="215" r="5"/><circle cx="140" cy="275" r="5"/><circle cx="60" cy="295" r="4"/>
    <path d="M35 248 90 217M100 218 136 271M34 254 57 292M64 294 135 277"/></g>
  ${place(50, 64, 64)}
  <text x="82" y="160" text-anchor="middle" font-family="Segoe UI, Arial, sans-serif" font-size="22" font-weight="600" fill="#ffffff">Nexus</text>
  <text x="82" y="180" text-anchor="middle" font-family="Segoe UI, Arial, sans-serif" font-size="10" fill="#99f6e4">Network Intelligence</text>
</svg>`
const w = await draw(164, 314, welcome)
writeFileSync(join(here, 'welcome.bmp'), bmp(164, 314, w.rgba))
const headerSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="150" height="57"><rect width="150" height="57" fill="#ffffff"/>${place(104, 11, 34)}</svg>`
const hd = await draw(150, 57, headerSvg)
writeFileSync(join(here, 'header.bmp'), bmp(150, 57, hd.rgba))
await browser.close()
console.log('wrote nexus.ico, welcome.bmp, header.bmp')
