/**
 * Flow: two tabs of one origin share the session store and key vault. Tab A's
 * otp verify is canceled while its requests are in flight, and tab B signs in
 * meanwhile. A canceled verify must store nothing, so B's session survives.
 *
 * Each tab gets its own module instance, as separate tabs do, so A's verify
 * does not queue B's sign-in behind it in the in-process key-transition queue.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { ApiKeyStamper, PasskeyStamper } from '../stampers/types.js'
import type { StorageAdapter } from '../storage/manager.js'
import { SessionType } from '../types/session.js'

// The bundle and signature need a real enclave key; the flow under test is what
// happens around them.
vi.mock('../utils/encryptOtpAttempt.js', () => ({
  encryptOtpAttempt: async ({ publicKey }: { publicKey: string }) => publicKey,
}))
vi.mock('../utils/buildClientSignature.js', () => ({
  buildClientSignature: async () => 'sig',
}))

const ORG_A = 'org-a'
const ORG_B = 'org-b'

const sessionKey = (nth: number) => `02${String(nth).padStart(64, '0')}`

/** One vault: the active key is shared, a pending rotation is per tab. */
function sharedVault() {
  let minted = 0
  let active: string | null = null
  const tab = (): ApiKeyStamper & { pendingKey: () => string | null } => {
    let pending: string | null = null
    const stamp = async () => ({
      stampHeaderName: 'X-Stamp',
      stampHeaderValue: 'stamp',
    })
    return {
      stamp,
      clear: async () => {
        active = null
        pending = null
      },
      getPublicKey: async () => active,
      resetKeyPair: async () => {
        active = sessionKey(++minted)
      },
      prepareKeyRotation: async () => {
        pending = sessionKey(++minted)
        return pending
      },
      stampPending: stamp,
      signPending: async () => 'sig',
      commitKeyRotation: async () => {
        if (pending) active = pending
        pending = null
      },
      discardKeyRotation: async () => {
        pending = null
      },
      sign: async () => 'sig',
      pendingKey: () => pending,
    }
  }
  return { tab, activeKey: () => active }
}

function sharedStorage(): StorageAdapter {
  const store = new Map<string, string>()
  return {
    getItem: (key) => store.get(key) ?? null,
    setItem: (key, value) => {
      store.set(key, value)
    },
    removeItem: (key) => {
      store.delete(key)
    },
  }
}

const passkeyStamper: PasskeyStamper = {
  stamp: async () => ({ stampHeaderName: 'X-Stamp', stampHeaderValue: 's' }),
  clear: async () => {},
  register: async () => ({
    attestation: {
      attestationObject: 'ao',
      clientDataJson: 'cdj',
      credentialId: 'cred-1',
    },
    encodedChallenge: 'challenge',
  }),
}

const sessionToken = (publicKey: string, org: string) =>
  `hdr.${btoa(
    JSON.stringify({
      exp: Date.now() + 3_600_000,
      public_key: publicKey,
      session_type: SessionType.READ_WRITE,
      user_id: `user-of-${org}`,
      organization_id: org,
    }),
  )}.sig`

const deferred = () => {
  let resolve!: () => void
  const promise = new Promise<void>((r) => {
    resolve = r
  })
  return { promise, resolve }
}

const json = (payload: unknown) =>
  new Response(JSON.stringify(payload), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  })

/**
 * The verification token carries the sealed key and the code, and the code
 * names the org it signs in to. `hold` keeps one code's step waiting; a held
 * otp verify honors its signal like `fetch`, a held login ignores it, as if
 * its response had already arrived.
 */
function stubServers(hold: { code: string; step: 'verify' | 'login' }) {
  const reached = deferred()
  const release = deferred()
  const waitFor = async (signal: AbortSignal | null | undefined) => {
    reached.resolve()
    if (hold.step === 'login') return release.promise
    await new Promise<void>((resolve, reject) => {
      release.promise.then(resolve)
      signal?.addEventListener('abort', () => reject(signal.reason))
    })
  }
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      const path = String(url)
      const body = init?.body ? JSON.parse(String(init.body)) : {}
      if (path.includes('server-info/parent-org-id')) {
        return json({ parentOrgId: 'parent-org' })
      }
      if (path.includes('server-info/auth-proxy-id')) {
        return json({ authProxyConfigId: 'proxy-1' })
      }
      if (path.includes('/v1/otp_verify_v2')) {
        const code = body.otpId as string
        if (code === hold.code && hold.step === 'verify') {
          await waitFor(init?.signal)
        }
        return json({ verificationToken: `${code}|${body.encryptedOtpBundle}` })
      }
      if (path.includes('/auth/login/otp')) {
        const [code, publicKey] = String(body.verificationToken).split('|')
        if (code === hold.code && hold.step === 'login') {
          await waitFor(init?.signal)
        }
        return json({ session: sessionToken(publicKey!, code!) })
      }
      return new Response('{}', { status: 404 })
    }),
  )
  return { reached: reached.promise, release: release.resolve }
}

/** A Core in its own module instance, as a separate tab has. */
async function openTab(
  vault: ReturnType<typeof sharedVault>,
  storage: StorageAdapter,
) {
  vi.resetModules()
  const { createZeroDevWalletCore } = await import(
    './createZeroDevWalletCore.js'
  )
  const apiKeyStamper = vault.tab()
  const core = await createZeroDevWalletCore({
    projectId: 'proj',
    rpId: 'localhost',
    sessionStorage: storage,
    apiKeyStamper,
    passkeyStamper,
    proxyBaseUrl: 'https://kms.test.invalid/api/v1',
  })
  return { core, apiKeyStamper }
}

/** The otp id doubles as the org the code signs in to. */
const verify = (org: string, signal?: AbortSignal) =>
  ({
    type: 'otp',
    mode: 'verifyOtp',
    otpId: org,
    otpCode: '123456',
    otpEncryptionTargetBundle: 'bundle',
    signal,
  }) as const

const caught = (p: Promise<unknown>) =>
  p.then(
    () => 'RESOLVED' as const,
    (error: unknown) => error,
  )

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('otp verify: a canceled verify stores nothing', () => {
  it.each(['verify', 'login'] as const)(
    "keeps another tab's session when canceled during the %s request",
    async (step) => {
      const vault = sharedVault()
      const storage = sharedStorage()
      const servers = stubServers({ code: ORG_A, step })
      const tabA = await openTab(vault, storage)
      const tabB = await openTab(vault, storage)
      const controller = new AbortController()

      const verifyingA = caught(
        tabA.core.auth(verify(ORG_A, controller.signal)),
      )
      await servers.reached
      await tabB.core.auth(verify(ORG_B))
      const signedInB = await tabB.core.getSession()
      controller.abort()
      servers.release()

      const error = await verifyingA
      expect(error).toBeInstanceOf(DOMException)
      expect((error as DOMException).name).toBe('AbortError')
      expect(await tabA.core.getSession()).toEqual(signedInB)
      expect(signedInB?.organizationId).toBe(ORG_B)
      expect(vault.activeKey()).toBe(signedInB?.publicKey)
      expect(tabA.apiKeyStamper.pendingKey()).toBeNull()
    },
  )

  it('rejects at once for a signal already aborted, without a request', async () => {
    const vault = sharedVault()
    const storage = sharedStorage()
    stubServers({ code: 'none', step: 'verify' })
    const tab = await openTab(vault, storage)
    const fetchMock = vi.mocked(fetch)
    fetchMock.mockClear()

    const error = await caught(
      tab.core.auth(verify(ORG_A, AbortSignal.abort())),
    )

    expect((error as DOMException).name).toBe('AbortError')
    expect(fetchMock).not.toHaveBeenCalled()
    expect(await tab.core.getSession()).toBeUndefined()
  })

  it('stores the session of a verify whose signal never aborts', async () => {
    const vault = sharedVault()
    const storage = sharedStorage()
    stubServers({ code: 'none', step: 'verify' })
    const tab = await openTab(vault, storage)

    await tab.core.auth(verify(ORG_A, new AbortController().signal))

    const session = await tab.core.getSession()
    expect(session?.organizationId).toBe(ORG_A)
    expect(vault.activeKey()).toBe(session?.publicKey)
  })
})
