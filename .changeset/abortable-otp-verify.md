---
'@zerodev/wallet-core': patch
---

fix(core): an otp verify takes an `AbortSignal`, and one canceled before its session is stored never replaces the session another tab stored meanwhile
