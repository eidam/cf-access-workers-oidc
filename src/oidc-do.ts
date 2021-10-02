import { Router } from 'itty-router'
import {
  dateInSecs,
  generateKeyPair,
  getResponse,
  obj2encStr,
  str2ab,
} from './utils'
import { base64url } from 'rfc4648'
// @ts-ignore
import config from './../config.yml'
import { Env, ExchangeCode, Jwk, PrivateKey } from './types'

const keyAlg = {
  name: 'RSASSA-PKCS1-v1_5',
  modulusLength: 2048,
  publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
  hash: { name: 'SHA-256' },
}

export class OpenIDConnectDurableObject {
  state: DurableObjectState
  storage: DurableObjectStorage
  env: Env

  jwtTtl: number

  privateKey: PrivateKey
  codes: Map<string, ExchangeCode>
  jwks:  Map<string, Jwk>
  router: Router<any>

  constructor(state: DurableObjectState, env: Env) {
    this.state = state
    this.storage = state.storage
    this.env = env

    // `blockConcurrencyWhile()` ensures no requests are delivered until
    // initialization completes.
    this.state.blockConcurrencyWhile(async () => {
      this.jwtTtl = config.jwt_ttl || 600 // 10 minutes default

      this.codes = new Map()
      this.jwks = await this.storage.list()

      const router = Router()
      router.post('/sign', req => this.handleSign(req))
      router.get('/exchange/:code', req => this.handleExchangeCode(req))
      router.get('/jwks', req => this.handleGetJwks(req))
      router.patch('/jwks', req => this.handleCleanupJwks(req))

      router.all('/', req => getResponse(null, 400))
      this.router = router
    })
  }

  async fetch(req: Request) {
    try {
      return this.router.handle(req)
    } catch (e) {
      return getResponse(e, 500)
    }
  }

  // Exchange the OIDC code for a signed JWT token
  async handleExchangeCode(req) {
    const { code } = req.params
    const exchange = this.codes.get(code)
    return getResponse(exchange, exchange ? 200 : 404)
  }

  async handleSign(req) {
    const {
      payload,
      generate_exchange_code: generateExchangeCode,
      access_jwt: access_token,
    } = await req.json()

    const timestamp = dateInSecs(new Date())
    const newPayload = {
      ...payload,
      iat: timestamp,
      nbf: timestamp,
      exp: timestamp + this.jwtTtl,
    }

    // Generate new private key if there is none
    if (!this.privateKey) {
      const { privateKey, publicKey } = await generateKeyPair(keyAlg)
      // @ts-ignore
      const kid = crypto.randomUUID()

      this.privateKey = {
        id: kid,
        key: privateKey,
      }

      const newJwk = {
        last_signature: timestamp,
        key: {
          kid,
          use: 'sig',
          kty: publicKey.kty,
          alg: publicKey.alg,
          n: publicKey.n,
          e: publicKey.e,
        },
      }

      await this.storage.put(kid, newJwk)
      this.jwks.set(kid, newJwk)
    } else {
      // otherwise just add last_signature metadata to the public key
      this.jwks.get(this.privateKey.id).last_signature = timestamp
      await this.storage.put(
        this.privateKey.id,
        this.jwks.get(this.privateKey.id),
      )
    }

    // Construct and sign new JWT token
    const header = { alg: 'RS256', typ: 'JWT', kid: this.privateKey.id }
    const encodedMessage = `${obj2encStr(header)}.${obj2encStr(newPayload)}`
    const encodedMessageArrBuf = str2ab(encodedMessage)

    const signatureArrBuf = await crypto.subtle.sign(
      {
        name: keyAlg.name,
        hash: keyAlg.hash,
      },
      this.privateKey.key,
      encodedMessageArrBuf,
    )

    const signatureUint8Array = new Uint8Array(signatureArrBuf)
    const encodedSignature = base64url.stringify(signatureUint8Array, {
      pad: false,
    })
    const id_token = `${encodedMessage}.${encodedSignature}`

    let code
    if (generateExchangeCode) {
      // @ts-ignore
      code = crypto.randomUUID()
      this.codes.set(code, {
        id_token,
        access_token,
        expires_at: payload.exp, // access_token is original Cloudflare Access JWT, so pass the original exp
      })
    }

    // Return both id_token and code
    return getResponse({ id_token, code })
  }

  // Return all public keys
  handleGetJwks(req) {
    const keys = Array.from(this.jwks, ([kid, jwk]) => jwk.key)
    return getResponse({ keys })
  }

  // Cleanup public keys we wont need anymore
  handleCleanupJwks(req) {
    this.jwks.forEach((jwk:Jwk, kid:string) => {
      if (
        this.privateKey?.id !== kid &&
        jwk.last_signature + this.jwtTtl < dateInSecs(new Date())
      ) {
        this.jwks.delete(kid)
        this.storage.delete(kid)
      }
    })

    return getResponse('ok')
  }
}
