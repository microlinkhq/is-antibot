type HeadersLike =
  | { get(name: string): string | null | undefined }
  | Record<string, string | string[] | undefined>

declare namespace isAntibot {
  type Detection = 'headers' | 'cookies' | 'html' | 'url' | 'statusCode'
  type Technique = 'javascript' | 'captcha' | 'waf' | 'cookie'
  type ProviderName =
    | 'cloudflare'
    | 'vercel'
    | 'akamai'
    | 'datadome'
    | 'perimeterx'
    | 'shapesecurity'
    | 'kasada'
    | 'imperva'
    | 'reblaze'
    | 'cheq'
    | 'sucuri'
    | 'threatmetrix'
    | 'meetrics'
    | 'ocule'
    | 'recaptcha'
    | 'hcaptcha'
    | 'funcaptcha'
    | 'geetest'
    | 'cloudflare-turnstile'
    | 'friendly-captcha'
    | 'captcha-eu'
    | 'qcloud-captcha'
    | 'aliexpress-captcha'
    | 'houzz'
    | 'reddit'
    | 'google'
    | 'linkedin'
    | 'instagram'
    | 'youtube'
    | 'amazon'
    | 'anubis'
    | 'fullstory-challenge'
    | 'aws-waf'
    | 'weibo'
    | 'dribbble'
    | 'douban'
    | 'cloudfront'

  interface Input {
    headers?: HeadersLike
    html?: string
    body?: string
    url?: string
    statusCode?: number
    status?: number
  }

  interface Result {
    detected: boolean
    provider: ProviderName | string | null
    detection: Detection | null
    technique: Technique | null
  }

  type DetectionRule =
    | { header: string; equals: string }
    | { header: string; startsWith: string }
    | { header: string; exists: true; except?: string }
    | { header: string; oneOf: string[] }
    | { headerNamePattern: string; flags?: string }
    | { cookie: string }
    | { contains: string }
    | { regex: string; flags?: string }
    | { status: number }

  interface DetectorDetection {
    type: 'headers' | 'cookies' | 'html' | 'url' | 'status_code'
    technique?: Technique
    domain?: string
    domainWithoutSuffix?: string
    statusCodes?: number[]
    rules: DetectionRule[]
  }

  interface DetectorProvider {
    name: string
    detections: DetectorDetection[]
  }

  function createDetector(config?: {
    providers?: DetectorProvider[]
  }): (input?: Input) => Result

  function createHasCookie(
    headers: HeadersLike,
    getHeader?: (name: string) => string | string[] | null | undefined
  ): (patternList: string | readonly string[]) => boolean

  function createTestPattern(
    value?: string | null
  ): (
    pattern: string | RegExp | { type: 'contains'; value: string }
  ) => boolean

  const debug: {
    (...args: unknown[]): void
    [level: string]: (...args: unknown[]) => void
  }
}

declare function isAntibot(input?: isAntibot.Input): isAntibot.Result

export = isAntibot
