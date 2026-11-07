# JWT normative excerpts

Short excerpts of normative sentences, kept for conformance checking.
Source: RFC 7519 (JWT), RFC 7515 (JWS), RFC 8725 (JWT Best Current Practices).

## RFC 7519 — JSON Web Token

### §4.1.1 "iss" (Issuer) Claim
- The "iss" (issuer) claim identifies the principal that issued the JWT.
- The processing of this claim is generally application specific.

### §4.1.3 "aud" (Audience) Claim
- Each principal intended to process the JWT MUST identify itself with a value in the audience claim.
- If the principal processing the claim does not identify itself with a value in the "aud" claim when this claim is present, then the JWT MUST be rejected.
- In the general case, the "aud" value is an array of case-sensitive strings, each containing a StringOrURI value.
- In the special case when the JWT has one audience, the "aud" value MAY be a single case-sensitive string.

### §4.1.4 "exp" (Expiration Time) Claim
- The "exp" claim identifies the expiration time on or after which the JWT MUST NOT be accepted for processing.
- The processing of the "exp" claim requires that the current date/time MUST be before the expiration date/time listed in the "exp" claim.
- Implementers MAY provide for some small leeway, usually no more than a few minutes, to account for clock skew.

### §4.1.5 "nbf" (Not Before) Claim
- The "nbf" claim identifies the time before which the JWT MUST NOT be accepted for processing.
- The processing of the "nbf" claim requires that the current date/time MUST be after or equal to the not-before date/time listed in the "nbf" claim.

### §7.2 Validating a JWT
- If the JWT is not a valid JWS, the JWT MUST be rejected.
- The JWS MUST be validated; if signature validation fails, the JWT MUST be rejected.

## RFC 7515 — JSON Web Signature

### §5.2 Message Signature or MAC Validation
- The JWS Signature value MUST be validated against the signing input using the algorithm in the "alg" header.
- If any of the listed steps fail, the JWS MUST be rejected.

### §10.7 Unsecured JWS
- Implementations that support Unsecured JWSs MUST NOT accept such objects as valid unless the application specifies that it is acceptable.

## RFC 8725 — JWT Best Current Practices

### §3.1 Perform Algorithm Verification
- Libraries MUST enable the caller to specify a supported set of algorithms and MUST NOT use any other algorithms when performing cryptographic operations.
- The library MUST ensure that the "alg" or "enc" header specifies the same algorithm that is used for the cryptographic operation.

### §3.2 Use Appropriate Algorithms
- Applications MUST NOT use the "none" algorithm unless explicitly intended.

### §3.8 Validate Issuer and Subject
- If a JWT contains an "iss" claim and the application expects a particular issuer, the application MUST validate the issuer.

### §3.9 Validate Audience
- If the same issuer can issue JWTs that are intended for use by more than one relying party or application, the JWT MUST contain an "aud" claim, and the relying party MUST validate it.

### §3.5 Validate All Cryptographic Operations
- All cryptographic operations in the JWT MUST be validated and the entire JWT MUST be rejected if any of them fail.

### Signature comparison (timing)
- Signature comparison SHOULD use a constant-time comparison to avoid timing side channels.
