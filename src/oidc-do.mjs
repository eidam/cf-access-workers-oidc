import { Router } from 'itty-router'
import { v4 as uuidv4 } from 'uuid'
import {
  dateInSecs,
  generateKeyPair,
  getResponse,
  obj2encStr,
  str2ab,
} from './utils'
import { base64url } from 'rfc4648'
import config from './../config.yml'

const keyAlg = {
  name: 'RSASSA-PKCS1-v1_5',
  modulusLength: 2048,
  publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
  hash: { name: 'SHA-256' },
}

export class OpenIDConnectDurableObject {
  constructor(state, env) {
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
      router.post('/sign', (req) => this.handleSign(req))
      router.get('/exchange/:code', (req) => this.handleExchangeCode(req))
      router.get('/jwks', (req) => this.handleGetJwks(req))
      router.patch('/jwks', (req) => this.handleCleanupJwks(req))

      router.all('/', (req) => getResponse(null, 400))
      this.router = router
    })
  }

  async fetch(req) {
    try {
      // @ts-ignore
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
      const kid = uuidv4()

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
      code = uuidv4()
      this.codes.set(code, {
        id_token,
        access_token,
        expires_in: 60, // exchange code lives in Durable Object memory only
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
    this.jwks.forEach((jwk, kid) => {
      if (
        this.privateKey?.id !== kid &&
        jwk.last_signature + this.jwtTtl < dateInSecs(new Date())
      ) {
        this.jwks.delete(kid)
        this.state.waitUntil(this.storage.delete(kid))
      }
    })

    return getResponse('ok')
  }
}
