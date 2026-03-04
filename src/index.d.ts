import type Debug from 'debug-logfmt'

/**
 * All supported antibot and challenge providers.
 */
export type Provider =
  | 'cloudflare'
  | 'vercel'
  | 'akamai'
  | 'datadome'
  | 'perimeterx'
  | 'shapesecurity'
  | 'kasada'
  | 'imperva'
  | 'recaptcha'
  | 'hcaptcha'
  | 'funcaptcha'
  | 'geetest'
  | 'cloudflare-turnstile'
  | 'aws-waf'

/**
 * Headers object that can be either a plain object or a Headers-like interface.
 */
export type Headers = Record<string, string | undefined> | {
  get(name: string): string | null
  [key: string]: unknown
}

/**
 * Options for the isAntibot function.
 */
export interface IsAntibotOptions {
  /**
   * Response headers from the request.
   * Can be a plain object or a Headers-like interface.
   */
  headers?: Headers
  /**
   * Response body content.
   */
  body?: string
  /**
   * Request URL.
   */
  url?: string
}

/**
 * Result of the antibot detection.
 */
export interface AntibotResult {
  /**
   * Whether an antibot/challenge was detected.
   */
  detected: boolean
  /**
   * The provider that was detected, or null if no antibot was found.
   */
  provider: Provider | null
}

/**
 * Detect if a response contains an antibot challenge or CAPTCHA.
 *
 * Supports detection for:
 * - Cloudflare (challenge pages, Turnstile)
 * - Vercel (challenge mode)
 * - Akamai (bot management)
 * - DataDome (bot detection)
 * - PerimeterX (now Arkose)
 * - Shape Security
 * - Kasada
 * - Imperva/Incapsula
 * - reCAPTCHA
 * - hCaptcha
 * - FunCaptcha (Arkose Labs)
 * - GeeTest
 * - AWS WAF
 *
 * @param options - Options containing headers, body, and url
 * @returns Detection result with provider information
 *
 * @example
 * ```ts
 * import { isAntibot } from 'is-antibot'
 *
 * const result = isAntibot({
 *   headers: { 'cf-mitigated': 'challenge' },
 *   body: '',
 *   url: 'https://example.com'
 * })
 *
 * console.log(result)
 * // { detected: true, provider: 'cloudflare' }
 * ```
 *
 * @example
 * ```ts
 * // Check if response contains any antibot challenge
 * const result = isAntibot({ headers, body, url })
 * if (result.detected) {
 *   console.log(`Detected ${result.provider} challenge`)
 * }
 * ```
 */
export function isAntibot(options?: IsAntibotOptions): AntibotResult

/**
 * Debug logger for is-antibot.
 */
export const debug: Debug.Debug

/**
 * Test if a value matches a pattern (string contains or regex).
 *
 * @param value - The value to test
 * @param pattern - The pattern to match against
 * @param isRegex - Whether to treat the pattern as a regex
 * @returns True if the value matches the pattern
 */
export function testPattern(
  value: string | undefined | null,
  pattern: string,
  isRegex?: boolean
): boolean

export default typeof isAntibot
