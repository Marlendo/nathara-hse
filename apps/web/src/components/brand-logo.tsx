import { GeneratedValue } from '@/i18n/generated'
import { PRODUCT_NAME } from '@/lib/brand'
// Nathara HSE brand logo — shield-and-check mark with a "NATHARA HSE"
// wordmark: a protection shield (safety) closed by an amber verification
// check.
// All ink strokes use `currentColor` (navy in light mode, near-white in dark);
// the check and "HSE" stay brand amber in both themes. Every shape carries a
// normalized pathLength so the splash can draw the logo in.
//
// Exports:
//   <Logo />        full horizontal lockup (mark + "NATHARA HSE" wordmark)
//   <LogoMark />    shield only (square-ish, for tight spots)
//   <BrandSplash /> full-screen draw-in animation for route loading
// Pass `animated` for the looping shimmer (CSS-only, respects
// prefers-reduced-motion — keyframes live in globals.css under "Brand logo").

import type { CSSProperties, SVGProps } from 'react'
import { cn } from '@beaconhs/ui'

const BRAND_AMBER = '#F5A623'

const INK_CLASS = 'text-[#1B2B4A] dark:text-slate-100'

type Mode = 'static' | 'loop' | 'draw'

const delay = (s: number) => ({ '--bd': `${s}s` }) as CSSProperties

const FONT_STACK =
  'system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif'

/* --------------------------------- The mark ------------------------------- */
// Shield drawn in a 64 × 64 box: outline first, then the verification check.
// Paths run outer → inner so staggered delays read as closing the shield.

const MARK_STRUCTURE = [
  'M32 7L52 14.5V31C52 44.5 43.5 54 32 57.5C20.5 54 12 44.5 12 31V14.5Z',
]

const MARK_CHECK = ['M23 31.5L29.5 38L42 24.5']

function MarkArt({ mode }: { mode: Mode }) {
  const draw = mode === 'draw'
  const animated = mode !== 'static'
  const strokeCls = draw ? 'brand-stroke-draw' : animated ? 'brand-stroke-loop' : undefined
  return (
    <>
      <GeneratedValue
        value={
          animated ? (
            <filter id="nhs-glow" x="-150%" y="-150%" width="400%" height="400%">
              <feGaussianBlur stdDeviation="3" />
            </filter>
          ) : null
        }
      />
      <g
        fill="none"
        stroke="currentColor"
        strokeWidth={5}
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <GeneratedValue
          value={MARK_STRUCTURE.map((d, i) => (
            <path
              key={d}
              d={d}
              {...(animated
                ? { pathLength: 1, className: strokeCls, style: delay(0.05 + i * 0.06) }
                : {})}
            />
          ))}
        />
      </g>
      {/* verification check — lit amber when animated */}
      <GeneratedValue
        value={
          animated ? (
            <circle
              cx={32}
              cy={32}
              r={24}
              fill={BRAND_AMBER}
              opacity={0.45}
              filter="url(#nhs-glow)"
              className={draw ? 'brand-glow-draw' : 'brand-glow-loop'}
              style={delay(0.85)}
            />
          ) : null
        }
      />
      <g
        fill="none"
        stroke={BRAND_AMBER}
        strokeWidth={6}
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <GeneratedValue
          value={MARK_CHECK.map((d, i) => (
            <path
              key={d}
              d={d}
              {...(animated
                ? { pathLength: 1, className: strokeCls, style: delay(0.5 + i * 0.07) }
                : {})}
            />
          ))}
        />
      </g>
    </>
  )
}

/* ------------------------------- The wordmark ---------------------------- */
// "NATHARA" in ink + "HSE" in amber, set in the platform sans (no webfont
// dependency — the logo must render inside the boot splash before any
// font loads). textLength pins the exact advance width so the lockup never
// clips or reflows across platforms. The wordmark fades in (no loop pulse)
// while the shield keeps the draw cycle.

const WORD_X = 70 // gap between mark and wordmark
const WORD_BASELINE = 41
const WORD_SIZE = 29
const NATHARA_ADVANCE = 150
const HSE_GAP = 12
const HSE_ADVANCE = 72
const HSE_X = WORD_X + NATHARA_ADVANCE + HSE_GAP
const LOCKUP_W = Math.ceil(HSE_X + HSE_ADVANCE + 8)
const LOCKUP_H = 64

function WordmarkArt({ mode }: { mode: Mode }) {
  const draw = mode === 'draw'
  return (
    <GeneratedValue
      value={
        <g
          aria-hidden="true"
          fontFamily={FONT_STACK}
          fontSize={WORD_SIZE}
          fontWeight={800}
          letterSpacing={1}
        >
          <text
            x={WORD_X}
            y={WORD_BASELINE}
            fill="currentColor"
            textLength={NATHARA_ADVANCE}
            lengthAdjust="spacingAndGlyphs"
            {...(draw ? { className: 'brand-text-draw', style: delay(0.5) } : {})}
          >
            NATHARA
          </text>
          <text
            x={HSE_X}
            y={WORD_BASELINE}
            fill={BRAND_AMBER}
            textLength={HSE_ADVANCE}
            lengthAdjust="spacingAndGlyphs"
            {...(draw ? { className: 'brand-text-draw', style: delay(0.8) } : {})}
          >
            HSE
          </text>
        </g>
      }
    />
  )
}

/* ------------------------------- Components ------------------------------ */

type LogoProps = SVGProps<SVGSVGElement> & {
  /** Loop the shimmer + lit check. */
  animated?: boolean
  /** Draw the whole logo in once, then keep the shield looping (splash). */
  draw?: boolean
}

export function LogoMark({ animated, draw, className, ...rest }: LogoProps) {
  const mode: Mode = draw ? 'draw' : animated ? 'loop' : 'static'
  return (
    <svg
      viewBox="0 0 64 64"
      role="img"
      aria-label={PRODUCT_NAME}
      className={cn('h-8 w-auto', INK_CLASS, className)}
      {...rest}
    >
      <MarkArt mode={mode} />
    </svg>
  )
}

export function Logo({ animated, draw, className, ...rest }: LogoProps) {
  const mode: Mode = draw ? 'draw' : animated ? 'loop' : 'static'
  return (
    <svg
      viewBox={`0 0 ${LOCKUP_W} ${LOCKUP_H}`}
      role="img"
      aria-label={PRODUCT_NAME}
      className={cn('h-8 w-auto', INK_CLASS, className)}
      {...rest}
    >
      <g transform="translate(4 4) scale(0.875)">
        <MarkArt mode={mode} />
      </g>
      <WordmarkArt mode={mode} />
    </svg>
  )
}

/** Full-screen brand splash: the logo draws itself in, then the shield keeps
 *  sweeping. Used only by the tab's startup overlay. */
export function BrandSplash() {
  return (
    <div className="flex h-dvh w-full items-center justify-center bg-slate-50 dark:bg-slate-950">
      <Logo draw className="h-14 w-auto sm:h-[4.5rem]" />
    </div>
  )
}
