declare global {
    interface DurableObjectState {
        blockConcurrencyWhile<T>(callback: () => Promise<T>): Promise<T>
    }
}

export interface Env {}

export interface ExchangeCode {
    id_token: string,
    access_token: string,
    expires_at: number
}

export interface PrivateKey {
    id: string,
    key: CryptoKey,
}

export interface JwkKey {
    kid: string,
    use: string,
    kty: string,
    alg: string,
    n: number,
    e: number
}

export interface Jwk {
    last_signature: number,
    key: JwkKey,
}