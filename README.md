Xiaomi NetEase Integration - Hardcoded RSA Private Key

Summary
The com.xiaomi.aicr package (Xiaomi's NetEase Cloud Music integration) contains a hardcoded RSA private key in its assets.

Path:
assets/thirdpartyaction/com.netease.cloudmusic/private_key_pkcs8.pem

This is a private key used to:
- Sign JSON requests to NetEase servers (EncryptHelper.java)
- Decrypt sensitive user session tokens (realToken) via RSAUtils.decryptByPrivateKey

Why This Is Not Informative
Xiaomi's Claim: "Hard-coded or recoverable keys in APKs are non-issues"
Reality: This is a private key. It is not "recoverable" — it is statically exposed in the application package.

Xiaomi's Claim: "Client-side issue only"
Reality: The server trusts this key to authenticate the client. Exposure allows full impersonation.

Xiaomi's Claim: "No impact"
Reality: Any attacker with this key can impersonate the official Xiaomi application to NetEase services and decrypt intercepted user sessions.

Impact
Global Impersonation
An attacker can forge valid signatures for requests to NetEase, making malicious traffic appear as if it originated from the official Xiaomi app.

Mass Decryption / Account Takeover
The private key is used to decrypt user session tokens (realToken). An attacker with network access (MitM) can intercept encrypted traffic, decrypt realToken, and take over user accounts without credentials.

Broken Non-Repudiation
Xiaomi can no longer cryptographically prove which requests originated from its own application. The trust model between Xiaomi and NetEase is compromised.

Technical Details
- Key Format: PKCS#8 PEM
- Algorithm: RSA (2048-bit)
- Usage: Request signing and response decryption
- Affected Class: com.xiaomi.aicr.actionprovider.neteasecloudmusic.Config
- Verification: The private key matches the public key hardcoded in the same class

Vendor Response
Reported to Xiaomi via HackerOne (#3516708) on 2026-01-19.
Closed as "Informative" on 2026-01-26 with the note:
"Hard-coded or recoverable keys in APKs are considered non-issues."

Mediation was requested and ignored. A mutual disclosure request was filed and later withdrawn.

No CVE has been assigned. No bounty was issued. No fix has been confirmed.

CVE Status
No CVE assigned. Submitted to VulDB for analysis and assignment.

Timeline
2026-01-19: Reported to Xiaomi (HackerOne #3516708)
2026-01-26: Closed as "Informative"
2026-02-12: Public PoC and VulDB submission

Repository
https://github.com/Danimlzg/xiaomi-netease-private-key-exposure
