// Regenerates the raster brand icons (PWA manifest icons, apple-touch icon,
// PNG favicon fallback) from the SVG shield-and-check mark. Keep the path
// data in sync with components/brand-logo.tsx. Run from anywhere:
//
//   bun apps/web/scripts/generate-brand-icons.mjs

import { mkdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import sharp from 'sharp'

const NAVY = '#1B2B4A'
const AMBER = '#F5A623'

// Full shield-and-check mark, 64 × 64 design space (mirror of brand-logo.tsx).
const mark = (ink) => `
  <g fill="none" stroke="${ink}" stroke-width="5" stroke-linecap="round" stroke-linejoin="round">
    <path d="M32 7L52 14.5V31C52 44.5 43.5 54 32 57.5C20.5 54 12 44.5 12 31V14.5Z" />
  </g>
  <g fill="none" stroke="${AMBER}" stroke-width="6" stroke-linecap="round" stroke-linejoin="round">
    <path d="M23 31.5L29.5 38L42 24.5" />
  </g>`

// Navy tile with the shield mark centered at `scale` of the tile height.
function tile(size, scale) {
  const h = 64 * (size / 64) * scale
  const s = h / 64
  const w = 64 * s
  const x = (size - w) / 2
  const y = (size - h) / 2
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}">
    <rect width="${size}" height="${size}" fill="${NAVY}" />
    <g transform="translate(${x.toFixed(1)} ${y.toFixed(1)}) scale(${s.toFixed(3)})">${mark('#F4F7FB')}</g>
  </svg>`
}

const faviconSvg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">${mark(NAVY)}</svg>`

// Monochrome silhouette for the Android push-notification badge. The platform
// masks the badge to its alpha channel and tints it with the system colour, so
// we render the shield filled solid-white on a transparent background.
const badgeSvg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <g fill="#fff" stroke="#fff" stroke-width="5" stroke-linecap="round" stroke-linejoin="round">
    <path d="M32 7L52 14.5V31C52 44.5 43.5 54 32 57.5C20.5 54 12 44.5 12 31V14.5Z" />
  </g>
</svg>`

const here = dirname(fileURLToPath(import.meta.url))
const webRoot = join(here, '..')
const iconsDir = join(webRoot, 'public/icons')
mkdirSync(iconsDir, { recursive: true })

const render = (svg, size, file) =>
  sharp(Buffer.from(svg), { density: 300 })
    .resize(size, size)
    .png()
    .toFile(file)
    .then(() => console.log('  ✓', file))

await Promise.all([
  render(tile(512, 0.68), 192, join(iconsDir, 'icon-192.png')),
  render(tile(512, 0.68), 512, join(iconsDir, 'icon-512.png')),
  render(tile(512, 0.55), 512, join(iconsDir, 'maskable-512.png')),
  render(tile(512, 0.66), 180, join(webRoot, 'src/app/apple-icon.png')),
  render(faviconSvg, 64, join(webRoot, 'src/app/icon1.png')),
  render(badgeSvg, 72, join(iconsDir, 'badge-72.png')),
])
console.log('Brand icons regenerated.')
