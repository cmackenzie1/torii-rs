# Magic Link Login Flow

## Phase 1: Request

1. User enters email on login form
2. Server returns generic message regardless of whether account exists (prevents enumeration)
3. Response time is consistent for both cases
4. Rate-limit requests per email/IP (CAPTCHA after threshold)

## Phase 2: Token Generation & Delivery

5. Generate token: cryptographically random, sufficiently long (128+ bits), linked to user
6. Store hash of token server-side (not plaintext), with expiration (~15-20 min)
7. **Hard-code the URL domain** (never use `Host` header—prevents Host Header Injection)
8. Send link via email over HTTPS: `https://app.example.com/auth/verify?token=<TOKEN>`

## Phase 3: Token Consumption (The Crawler Problem)

This is the key part to prevent email security scanners (Outlook SafeLinks, Proofpoint, etc.) and crawlers from consuming the token via GET:

9. **GET request to magic link → render confirmation page only** (no auth, no token consumption)
10. Page displays: "Click to complete login" button
11. **User clicks button → POST request with token**
12. **POST handler validates and consumes the token**, creates session

This two-step pattern ensures:

- GET requests from prefetchers/crawlers don't authenticate anyone
- Token is only consumed on intentional user action (POST)
- The token can even survive one prefetch GET since consumption requires POST

## Phase 4: Session Establishment

13. Validate token: exists, not expired, not already used
14. **Invalidate token immediately** (single-use)
15. Create session, issue session cookie with secure flags (`HttpOnly`, `Secure`, `SameSite=Strict`)
16. Invalidate any other active sessions for this user (optional, depends on UX requirements)

## Phase 5: Logging

17. Log: timestamp, IP, user-agent, success/failure, token identifier (not the token itself)
18. Alert on anomalies (multiple failures, geographic impossibilities)

---

## Key Protections Summary

| Threat | Mitigation |
|--------|------------|
| Email scanner prefetch | GET renders page only; POST consumes token |
| Token brute-force | Cryptographically random, long, rate-limited |
| Replay attacks | Single-use, short TTL |
| Host header injection | Hard-coded URL domain |
| User enumeration | Generic responses, consistent timing |
| Token leakage | Store hash server-side; HTTPS only |
