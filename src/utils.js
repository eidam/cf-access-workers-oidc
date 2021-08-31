import { base64url } from 'rfc4648'
import jwt_decode from 'jwt-decode'
import config from '../config.yml'

export const getClientConfig = (clientId) => {
  return config.clients.find((x) => x.client_id === clientId)
}

export const getClientSecret = (clientSecretKey, env) => {
  return env[clientSecretKey]
}

export const dateInSecs = (d) => Math.ceil(Number(d) / 1000)

export const getResponse = (body, status = 200, headers = {}) => {
  return new Response(typeof body !== 'string' ? JSON.stringify(body) : body, {
    status,
    headers: {
      'content-type': 'application/json',
      ...headers,
    },
  })
}

export const getCorsHeaders = (origin, headers = []) => {
  if (origin) {
    return {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Headers': headers.join(','),
    }
  } else {
    return {}
  }
}

export const getAllowedOrigin = (req, clientId) => {
  const reqOrigin = req.headers.get('origin')
  let allowOrigin

  if ((clientId = '*')) {
    allowOrigin = config.clients.some((client) =>
      client.cors_origins?.includes(reqOrigin),
    )
  } else {
    allowOrigin = getClientConfig(clientId)?.cors_origins?.includes(reqOrigin)
  }

  return allowOrigin ? reqOrigin : null
}

export const verifyJwtSignature = (jwsObject, jwk) => {
  const jwsSigningInput = jwsObject.split('.').slice(0, 2).join('.')
  const jwsSignature = jwsObject.split('.')[2]
  return crypto.subtle
    .importKey(
      'jwk',
      jwk,
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: { name: 'SHA-256' },
      },
      false,
      ['verify'],
    )
    .then((key) =>
      crypto.subtle.verify(
        { name: 'RSASSA-PKCS1-v1_5' },
        key,
        base64url.parse(jwsSignature, { loose: true }),
        new TextEncoder().encode(jwsSigningInput),
      ),
    )
}

export const obj2encStr = (object) => {
  return base64url.stringify(new TextEncoder().encode(JSON.stringify(object)), {
    pad: false,
  })
}

export const str2ab = (str) => {
  const buf = new ArrayBuffer(str.length)
  const bufView = new Uint8Array(buf)
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i)
  }
  return buf
}

export const getIssuer = (req) => {
  const url = new URL(req.url)
  return `https://${url.hostname}`
}

export const generateKeyPair = async (keyAlg) => {
  const keyPair = await crypto.subtle.generateKey(keyAlg, true, [
    'sign',
    'verify',
  ])

  if (!keyPair.privateKey || !keyPair.publicKey) {
    throw 'Generating of key pair failed'
  }

  const publicKey = await crypto.subtle.exportKey('jwk', keyPair.publicKey)

  return { privateKey: keyPair.privateKey, publicKey }
}

export const getDoStub = (env) => {
  const oidcDoId = env.DO_OIDC.idFromName('oidc')
  return env.DO_OIDC.get(oidcDoId)
}

// Verify Cloudflare Access JWT
export const verifyCloudflareAccessJwt = async (jwtToken, env) => {
  try {
    const header = jwt_decode(jwtToken, { header: true })
    const payload = jwt_decode(jwtToken)
    const jwk = await getCloudflareAccessJwk(header.kid, env)

    const verified = await verifyJwtSignature(jwtToken, jwk)
    if (!verified) throw 'JWT token could not be verified'

    if (!payload.aud.includes(config.cf_access_aud))
      throw "JWT token 'aud' is not valid"
    if (payload.iss !== `https://${config.cf_access_team}.cloudflareaccess.com`)
      throw 'JWT token issuer is not valid'

    const currentTime = Math.floor(Date.now() / 1000)
    if (payload.exp < currentTime) throw 'JWT token is expired'
    if (payload.iat > currentTime) throw 'JWT token issued in the future'
    if (payload.nbf > currentTime) throw 'JWT token is not valid yet'

    return {
      success: true,
      header,
      payload,
    }
  } catch (e) {
    return {
      success: false,
      error: e.toString(),
    }
  }
}

// Get Cloudflare Access jwk for key id
const getCloudflareAccessJwk = async (kid, env) => {
  const apiRes = await fetch(
    `https://${config.cf_access_team}.cloudflareaccess.com/cdn-cgi/access/certs`,
  )
  return (await apiRes.json()).keys.find((x) => x.kid === kid)
}

// Get Cloudflare Access groups and filter them for an email
export const getCloudflareAccessGroups = async (email, env) => {
  const apiRes = await fetch(
    `https://api.cloudflare.com/client/v4/accounts/${config.cf_account_id}/access/groups`,
    {
      headers: {
        Authorization: `Bearer ${env.SECRET_CF_API_TOKEN}`,
      },
    },
  )

  const groups = (await apiRes.json()).result
  const groupsMatch = groups
    .filter((group) =>
      group.include.find(
        (rule) =>
          rule.email?.email === email ||
          rule.email_domain?.domain === email.split('@')[1],
      ),
    )
    .map((group) => group.name)

  return groupsMatch
}
