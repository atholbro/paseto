# PASETO: Platform-Agnostic Security Tokens
[![Build](https://github.com/atholbro/paseto/actions/workflows/build.yml/badge.svg)](https://github.com/atholbro/paseto/actions/workflows/build.yml)
[![Maven Central Version](https://img.shields.io/maven-central/v/net.aholbrook.paseto/paseto)](https://central.sonatype.com/artifact/net.aholbrook.paseto/paseto)
[![codecov](https://codecov.io/gh/atholbro/paseto/branch/master/graph/badge.svg)](https://codecov.io/gh/atholbro/paseto)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)


A Kotlin/JVM Implementation of Platform-Agnostic Security Tokens - https://paseto.io

Paseto is everything you love about JOSE (JWT, JWE, JWS) without any of the
[many design deficits that plague the JOSE standards](https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid).

## Table of Contents
- [What is Paseto?](#what-is-paseto)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [Token Version](#token-version)
  - [Token Purpose](#token-purpose)
- [Keys](#keys)
  - [Key Generation](#key-generation)
  - [Key Loading](#key-loading)
  - [Key Rings](#key-rings)
  - [Key Lifecycles](#key-lifecycles)
  - [Key Saving](#key-saving)
- [Tokens](#tokens)
  - [Standard Claims](#standard-claims)
  - [Custom Claims](#custom-claims)
- [Footers](#footers)
  - [String Footers](#string-footers)
  - [Structured Claim Footers](#structured-claim-footers)
  - [Footer Verification During Decode](#footer-verification-during-decode)
  - [Footer Limits and Parsing](#footer-limits-and-parsing)
  - [Footer Parsing Modes](#footer-parsing-modes)
  - [Tainted Footers](#tainted-footers)
  - [Accessing Footer Claims](#accessing-footer-claims)
- [Rules Engine](#rules-engine)
  - [Rule Execution](#rule-execution)
  - [Built-in Rules](#built-in-rules)
  - [Default Rules](#default-rules)
  - [Custom Rules](#custom-rules)
  - [Reusing Rule Sets](#reusing-rule-sets)

## What is Paseto?

Paseto (Platform-Agnostic SEcurity TOkens) is a specification and reference implementation
for secure stateless tokens.

### Key Differences between Paseto and JWT

Unlike JSON Web Tokens (JWT), which gives developers more than enough rope with which to
hang themselves, Paseto only allows secure operations. JWT gives you "algorithm agility",
Paseto gives you "versioned protocols". It's incredibly unlikely that you'll be able to
use Paseto in [an insecure way](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries).

> **Caution:** Neither JWT nor Paseto were designed for
> [stateless session management](http://cryto.net/~joepie91/blog/2016/06/13/stop-using-jwt-for-sessions/).
> Paseto is suitable for tamper-proof cookies, but cannot prevent replay attacks
> by itself.

---

## Requirements

- JDK 17+

#### Supported Paseto Versions
|  Type  | V1 | V2 | V3 | V4 |
|:------:|:--:|:--:|:--:|:--:|
| local  | ✓  | ✓  | ✓  | ✓  |
| public | ✓  | ✓  | ✓  | ✓  |

#### Supported Features
|  Feature  | Status  |
|:---------:|:-------:|
| JsonToken |    ✓    |
|  PASERK   | planned |

## Installation
Add `net.aholbrook.paseto:paseto:0.9.0` your dependencies.

```gradle
dependencies {
    implementation('net.aholbrook.paseto:paseto:0.9.0')
}
```

## Usage

```kotlin
// First create a key to encrypt/decrypt the token.
// Please remember to save the key!
val key: SymmetricKey = SymmetricKey.generate(Version.V4)

// Next we create the token service which is used to encode and decode tokens
val service = tokenService(Version.V4, Purpose.Local { _ -> key })

// Create a token
val token: Token = token {
    tokenId = "session-123"
    audience = "mobile-app"
}

// Encode the token
val encoded: String = service.encode(token)

// And finally decode the previously encoded token
val decoded: Token = service.decode(encoded)
```

### Token Version
**TL;DR use V4**

When setting up the Token Service we selected Version.V4. There are 4 versions
available, here's a quick table to outline the differences:

| Purpose | NIST | Notes                                                                                                                                                                                     |
|---------|:----:|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| V1      | Yes  | Uses NIST-approved primitives: RSA-PSS for public tokens and AES-CTR + HMAC-SHA384 for local tokens. Considered legacy and mainly kept for compatibility.                                 |
| V2      |  No  | Uses modern non-NIST primitives: Ed25519 and XChaCha20-Poly1305. Designed for simplicity and strong security but not NIST compliant. Considered legacy and mainly kept for compatibility. |
| V3      | Yes  | Uses NIST primitives: ECDSA P-384 for public tokens and AES-CTR + HMAC-SHA384 for local tokens. Created specifically for NIST/FIPS environments.                                          |
| V4      |  No  | Uses modern non-NIST primitives: Ed25519 and XChaCha20-Poly1305 (same crypto family as V2 but with protocol improvements).                                                                |

Generally you should select V4 unless you require NIST primitives in which case you should use V3. If you decide to use
V3, please review the official PASETO [Questions For Security Auditors](https://github.com/paseto-standard/paseto-spec/blob/master/docs/Rationale-V3-V4.md#questions-for-security-auditors).
This library should meet these requirements however it has not been independently verified.

### Token Purpose
When creating a token service with PASETO, you must choose between two token
types: **local** and **public**.

| Purpose | Encrypted | Authentication | Asymmetric |
|---------|:---------:|:--------------:|:----------:|
| local   |     ✓     |       ✓        |            |
| public  |           |       ✓        |     ✓      |

Both token types include **authentication**, meaning any modification to the
token will be detected and rejected.

**Local tokens** are **encrypted & authenticated** using a symmetric key.
The same secret key is required to both create and read the token. This makes
local tokens appropriate when the same service both issues and consumes the
tokens.

**Public tokens** are **signed but not encrypted**. Their contents are visible
to anyone, but the signature can only be produced using the issuer’s private
key. Other parties can verify the token using the corresponding public key,
allowing them to confirm authenticity without being able to create valid
tokens themselves.

In short:
- **Local** → private, encrypted tokens shared between trusted parties.
- **Public** → readable tokens that can be verified by anyone with the public key but only issued by the holder of the private key.

### Example of a public token service
```kotlin
val keyPair = KeyPair.generate(Version.V4) // remember to save the keys!
val service = tokenService(Version.V4, Purpose.Public { keyPair.copy() })

val token = token { tokenId = "abc" }
val encoded = service.encode(token)
val decoded = service.decode(encoded)
```

---

## Keys
### Key Generation
Keys can be generated directly by the library.  Each PASETO version defines the
required key size and algorithm, so the generation functions take a `Version`
parameter.

For `local` tokens, a single `SymmetricKey` can be generated:
```kotlin
val key = SymmetricKey.generate(Version.V4)
```


For `public` tokens, a key pair can be generated:
```kotlin
val keyPair = KeyPair.generate(Version.V4)
```

This produces:
- an `AsymmetricSecretKey` used for signing
- an `AsymmetricPublicKey` used for verification

Key generation is typically performed once during system setup and the
resulting keys are stored in a secure location. *The same generation functions
are used for the other PASETO versions.*

### Key Loading
The two purposes use different key types. Local tokens use a `SymmetricKey`,
meaning the same key is used for both encryption and decryption. Public tokens
use an asymmetric key pair consisting of an `AsymmetricSecretKey` for signing
and an `AsymmetricPublicKey` for verifying the signature.

For this reason, the selected Purpose provides a lambda responsible for loading
the appropriate key material. When constructing the Token Service and selecting
the purpose, you also supply a function that loads the required key(s) for each
token operation.

```kotlin
val service = tokenService(
    version = Version.V4,
    purpose = Purpose.Local { _ ->
        SymmetricKey.ofBase64Url(loadKeyFromEnv(), Version.V4)
    }
)
```

#### Supported Loading Formats

Symmetric Keys:

| Method                              | Description                                |
|-------------------------------------|--------------------------------------------|
| `SymmetricKey.ofRawBytes()`         | Load key material directly from raw bytes. |
| `SymmetricKey.ofHex()`              | Load a key encoded as hexadecimal.         |
| `SymmetricKey.ofBase64Url()`        | Load a key encoded using Base64URL.        |

Asymmetric Secret Keys:

| Method                              | Description                                |
|-------------------------------------|--------------------------------------------|
| `AsymmetricSecretKey.ofRawBytes()`  | Load from raw private key bytes.           |
| `AsymmetricSecretKey.ofHex()`       | Load a hexadecimal encoded private key.    |
| `AsymmetricSecretKey.ofBase64Url()` | Load a Base64URL encoded private key.      |
| `AsymmetricSecretKey.ofPem()`       | Load a private key encoded as PEM.         |

Asymmetric Public Keys:

| Method                              | Description                                |
|-------------------------------------|--------------------------------------------|
| `AsymmetricPublicKey.ofRawBytes()`  | Load from raw public key bytes.            |
| `AsymmetricPublicKey.ofHex()`       | Load a hexadecimal encoded public key.     |
| `AsymmetricPublicKey.ofBase64Url()` | Load a Base64URL encoded public key.       |
| `AsymmetricPublicKey.ofPem()`       | Load a PEM encoded public key.             |

Key Pairs:

| Method                              | Description                                |
|-------------------------------------|--------------------------------------------|
| `KeyPair.ofPkcs12()`                | Load private/public key from a .p12 file   |

### Key Rings
The key loading lambda (keyProvider() function) receives the token's tainted
footer, allowing applications to select keys dynamically. This is useful for
implementing key rotation or key rings, where the footer contains metadata such
as a key identifier (kid).

Simple KeyRing Example:
```kotlin
val keyRing = mapOf<String, SymmetricKey>()

val service = tokenService(
    version = Version.V4,
    purpose = Purpose.Local { footer ->
        val kid = (footer as? TaintedClaimFooter)?.keyId
            ?: error("Missing key id")
        keyRing[kid] ?: error("Unknown key id")
    }
)
```

Because the footer is extracted before cryptographic verification, it is
represented as a tainted footer. Applications should treat these values as
untrusted input until the token has been successfully verified.

### Key Lifecycles
Key **material** is intended to be reused, but individual key **instances**
can optionally be configured to automatically clear themselves from memory
after use.

Keys support two lifecycle modes:

| Lifecycle    | Behavior                                                                            |
|--------------|-------------------------------------------------------------------------------------|
| `PERSISTENT` | The key instance remains usable after operations. This is the **default** behavior. |
| `EPHEMERAL`  | The key instance is cleared from memory after use.                                  |

When an **ephemeral** key is used in a PASETO operation, its internal key
material is securely zeroed once the operation completes. Any subsequent
attempt to use the same instance will throw a `KeyClearedException`.

This helps reduce the chance that sensitive key material could appear in
memory dumps or long-lived heap objects.

Example:
```kotlin
val key = SymmetricKey.generate(Version.V4, lifecycle = KeyLifecycle.EPHEMERAL)
val service = tokenService(Version.V4, Purpose.Local { _ -> key })

service.encode(token)
service.encode(anotherToken) // `KeyClearedException` will be thrown
```

**When using ephemeral keys, the keyProvider function should return a fresh
key instance for each operation.**

Keys that are loaded or generated are `PERSISTENT` by default. Copies created
using the `copy()` function are `EPHEMERAL` by default. Calling `clear()` will
zero the key material regardless of the lifecycle. The lifecycle only affects
the automatic clearing behavior performed internally after a cryptographic
operation. Attempting to use a cleared key, regardless of it's `lifecycle` will
raise a `KeyClearedException`.

Lifecycle rules do **not** apply to `AsymmetricPublicKey`.

### Key Saving
Keys can be exported to several formats for storage.

Symmetric Keys:

| Method                       | Description                    |
|------------------------------|--------------------------------|
| `SymmetricKey.toHex()`       | Export the key as hexadecimal. |
| `SymmetricKey.toBase64Url()` | Export the key as Base64URL.   |

Asymmetric Secret Keys:

| Method          | Description                            |
|-----------------|----------------------------------------|
| `toHex()`       | Export the private key as hexadecimal. |
| `toBase64Url()` | Export the private key as Base64URL.   |
| `toPem()`       | Export the private key in PEM format.  |

Asymmetric Public Keys:

| Method          | Description                           |
|-----------------|---------------------------------------|
| `toHex()`       | Export the public key as hexadecimal. |
| `toBase64Url()` | Export the public key as Base64URL.   |
| `toPem()`       | Export the public key in PEM format.  |



---

## Tokens
A PASETO token contains a collections of **claims** that describe the identity,
context, and validity of the token. These claims are stored in the token body
and are protected by the PASETO protocol.

The `Token` class represents the structured claims contained in a token.

### Standard Claims
The standard PASETO claims are all supported directly on the `Token` class:

| Field       | Claim | Description                                                                             |
|-------------|-------|-----------------------------------------------------------------------------------------|
| `issuer`    | `iss` | Identifies the principal that issued the token (typically your authentication service). |
| `subject`   | `sub` | Identifies the subject of the token, usually the user or entity the token represents.   |
| `audience`  | `aud` | Identifies the intended recipient of the token (e.g., a specific service or API).       |
| `expiresAt` | `exp` | The time after which the token must not be accepted.                                    |
| `notBefore` | `nbf` | The time before which the token must not be accepted.                                   |
| `issuedAt`  | `iat` | The time the token was issued.                                                          |
| `tokenId`   | `jti` | A unique identifier for the token.                                                      |

All time-based claims are stored as `Instant` values and truncated to **second
precision** when the token is built.

### Custom Claims

In addition to the standard claims, tokens may include arbitrary **custom
claims**.

Custom claims allow applications to include additional context such as:

- roles or permissions
- organization identifiers
- session metadata
- feature flags

*The claims API closely mirrors the `buildJsonObject` API from `kotlinx.serialization`.*

Example:

```kotlin
val token = token {
    issuer = "auth-service"
    subject = "user:123"

    claims {
        put("role", "admin")
        put("login_count", 42)
        put("active", true)
    }
}
```

#### Nested Objects
Nested objects can be created using claimObject:

```kotlin
claims {
    put("user", claimObject {
        put("id", "123")
        put("role", "admin")
    })
}
```

#### Arrays
Arrays can be created using claimArray:

```kotlin
claims {
    put("permissions", claimArray {
        add("read")
        add("write")
        add("delete")
    })
}
```

#### Reading Claims
Claims can be accessed through the ClaimElement API. Each element may be an
object, array, or primitive value.

```kotlin
val role = token.claims["role"]?.asType<String>()
```

Primitive values can also be accessed through the convenience properties:

| Property        | Type       |
|-----------------|------------|
| `stringOrNull`  | `String?`  |
| `booleanOrNull` | `Boolean?` |
| `intOrNull`     | `Int?`     |
| `longOrNull`    | `Long?`    |
| `doubleOrNull`  | `Double?`  |

For example:
```kotlin
val loginCount = token.claims["login_count"]?.primitiveOrNull?.intOrNull
```

Or for structured values:
```kotlin
val user = token.claims["user"]?.objectOrNull
val permissions = token.claims["permissions"]?.arrayOrNull
```

An internal escape hatch is also provided for accessing the raw JSON
representation of claims provided you have `kotlinx.serialization` available:
```kotlin
@OptIn(InternalApi::class)
val json = token.claimsJson()
```
*The escape hatch requires Opt-in as the API is subject to change, use only if
required and at your own risk.*

## Footers
PASETO supports an optional **footer** attached to the token. The footer is
**authenticated but not encrypted**, regardless of the token purpose. This means
its contents are visible but protected against modification once the token has
been verified.

Footers are commonly used to carry **metadata required to process the token**,
such as identifying which key should be used to verify it.

Two footer formats are supported.

| Type           | Description                                                                   |
|----------------|-------------------------------------------------------------------------------|
| `StringFooter` | A simple string value attached to the token.                                  |
| `ClaimFooter`  | A structured footer containing standard metadata fields and arbitrary claims. |

### String Footers

A string footer is the simplest form and is useful when only a small piece of
metadata needs to be attached.

```kotlin
val token = token {
    issuer = "auth-service"
    footer("key-2026-01")
}
```

A string footer is stored in a `StringFooter`. You can create a footer
outside the token builder via the same `footer(string)` function:
```kotlin
val basicStringFooter = footer("key-2026-02")
```

### Structured Claim Footers
Structured footers allow metadata and additional claims to be attached using
the footer {} DSL. These are stored in a `ClaimFooter`.

The PASETO standard reserves two footer claims:

| Field        | Claim | Description                                           |
|--------------|-------|-------------------------------------------------------|
| `keyId`      | `kid` | Identifies the key used to sign or encrypt the token. |
| `wrappedKey` | `wpk` | An optional wrapped key encoded as a PASERK.          |


These standard claims are supported directly on the footer builder DSL:
```kotlin
val token = token {
    issuer = "auth-service"

    footer {
        keyId = "key-2026-01"
        wrappedKey = "encrypted-key"
    }
}
```

A footer with structured claims is stored in a `ClaimFooter`. You can create a footer
outside the token builder via the same `footer { ... }` builder function.

**If you're using footer claims you should switch the parsing mode to `FooterParseMode.CLAIMS` for strict JSON decoding.** More on this below.

#### Custom Claims
Structured Footers support arbitrary claims using the same API as the `Token`.
You can set any claim except the two reserved keywords `kid` and `wpk`.

Example:
```kotlin
val footer = footer {
    keyId = "key-2026-01"
    put("routing", claimObject {
        put("cluster", "auth-cluster-a")
        put("environment", "production")
    })
    put("processing_hints", claimArray {
        add("cacheable")
        add("edge-verify")
    })
}
```

### Footer Verification During Decode
When decoding a token, an expected footer may optionally be provided. If a
footer is supplied, the decoded token footer must match exactly. If the footers
do not match, decoding will fail.

```kotlin
val expectedFooter = footer {
    keyId = "key-2026-01"
}

val token = service.decode(encodedToken, footer = expectedFooter)
// throws IncorrectFooterException if not an exact match
```
This ensures that the token was issued with the expected footer metadata.

### Footer Limits and Parsing
Footers are subject to several limits to prevent excessive memory usage and
protect against malicious inputs when parsing tokens.

These limits apply when **encoding** and **decoding** footers.

| Option      | Default | Description                                                    |
|-------------|---------|----------------------------------------------------------------|
| `parseMode` | `AUTO`  | The footer parse mode (AUTO, CLAIMS, STRING), more info below. |
| `maxLength` | `8192`  | Maximum allowed length of the footer string.                   |
| `maxDepth`  | `2`     | Maximum JSON object nesting depth for claim footers.           |
| `maxKeys`   | `512`   | Maximum number of keys allowed in a JSON footer.               |

If these limits are exceeded, decoding will fail and an exception will be thrown.

`maxDepth` and `maxKey` limits only apply when the footer is processed as JSON,
either via `AUTO` or `CLAIMS` parsing mode. All footers have the `maxLength`
limitation enforced.

### Footer Parsing Modes
Multiple strategies are supported for interpreting footer data when a token is
decoded.

| Mode     | Behavior                                                                                                                       |
|----------|--------------------------------------------------------------------------------------------------------------------------------|
| `AUTO`   | Attempts to parse object-like footer text (`{...}`) as JSON claims. If parsing fails, the footer is treated as a plain string. |
| `CLAIMS` | Requires the footer to be valid JSON. Parsing or validation failures will throw an exception.                                  |
| `STRING` | Always treats the footer as a plain string without attempting JSON parsing. Max length limit still applies                     |

Example configuration:

```kotlin
val service = tokenService(Version.V4, Purpose.Public { key.copy() }) {
    footerOptions {
        parseMode = FooterParseMode.CLAIMS
        maxLength = 4096
        maxDepth = 2
        maxKeys = 256
    }
}
```

### Tainted Footers
When parsing a token, the footer may be extracted before the token has been
cryptographically verified. In this case the footer must be treated as
untrusted input.

For this reason the library exposes a separate type:

| Type                  | Description                                  |
|-----------------------|----------------------------------------------|
| `TaintedStringFooter` | Unverified variant of `StringFooter`.        |
| `TaintedClaimFooter`  | Unverified variant of `ClaimFooter`.         |

These types indicate that the footer may have been tampered with and should
not be trusted until the token has been successfully verified.

A verified footer can be converted to its tainted representation using:
```kotlin
val footer = footer("abcd")
val tainted = footer.taint()
```
This allows comparisons between expected footer values and those extracted
from an incoming token.

*There is no inverse operation by design.*

### Accessing Footer Claims
Footer claims are store in the same `ClaimObject` as used for `Token`, so the
access pattern is identical.

Example:
```kotlin
val region = footer.claims["region"]?.asType<String>()
```

An internal escape hatch is also provided for accessing the raw JSON
representation of footer claims provided you have `kotlinx.serialization`
available:
```kotlin
@OptIn(InternalApi::class)
val json = footer.claimsJson()
```
*The escape hatch requires Opt-in as the API is subject to change, use only if
required and at your own risk.*

---

## Rules Engine

When a token is encoded or decoded, the library can apply a set of **validation rules**
to verify that the token's claims satisfy application requirements.

Rules are configured on the `TokenService` and are executed automatically during
token encoding and decoding.

Example configuration:

```kotlin
val service = tokenService(Version.V4, Purpose.Public { keyPair }) {
    rules {
        issuedBy = IssuedBy("auth-service")
        forAudience = ForAudience("payments-api")
        subject = Subject("user:42")
    }
}
```

If any rule fails during validation, decoding will throw a
`MultipleValidationErrorsException` containing all rule failures.

### Rule Execution
Rules are executed sequentially in the following order:
1. Standard claim rules
2. Custom rules, in the order they were added

Each rule receives:
- the decoded Token
- the current Mode (ENCODE or DECODE)
- the results of previously executed rules

Rules may either:
- complete successfully (RuleVerified)
- throw a RuleValidationException (RuleFailed)

All rule failures are collected and reported together as a
`MultipleValidationErrorsException`.

### Built-in Rules
Several rules that validate common PASETO claims are included with the library.

| Rule           | Claim               | Description                                              |
|----------------|---------------------|----------------------------------------------------------|
| `IssuedBy`     | `iss`               | Ensures the token was issued by the expected issuer.     |
| `ForAudience`  | `aud`               | Ensures the token is intended for the expected audience. |
| `Subject`      | `sub`               | Ensures the token subject matches the expected value.    |
| `IdentifiedBy` | `jti`               | Ensures the token identifier matches the expected value. |
| `IssuedInPast` | `iat`               | Ensures the token was not issued in the future.          |
| `NotBefore`    | `nbf`               | Ensures the token is not used before its valid time.     |
| `NotExpired`   | `exp`               | Ensures the token has not expired.                       |
| `ValidAt`      | `iat`, `nbf`, `exp` | Ensures the token is valid at the current time.          |

### Default Rules
Two rules are enabled by default.

| Rule           | Purpose                                       |
|----------------|-----------------------------------------------|
| `IssuedInPast` | Ensures tokens were not issued in the future. |
| `NotExpired`   | Ensures tokens are not expired.               |

These can be overridden or removed when building the ruleset:
```kotlin
tokenService(Version.V4, Purpose.Local { _ -> key }) {
    rules {
        issuedInPast = null
        notExpired = null
    }
}
```

If you wish to create tokens within an expiry time you must disable the
`notExpired` rule by setting it to null using the builder.

### Custom Rules
Applications may define additional validation logic using `CustomRule`.

```kotlin
val customRule = CustomRule { token, mode, results ->
    val tier = token.claims["tier"]?.asType<String>() ?: return@CustomRule

    if (!tier.constantTimeEquals("premium")) {
        throw RuleValidationException("premium tier required", "tier", token)
    }
}

rules {
    forAudience = ForAudience("abc")
    customRules.add(customRule)
}
```

Custom rules run alongside built-in rules and participate in the same
validation pipeline.

#### Rule Modes
Rules run in two contexts:

| Mode     | Description                                                 |
|----------|-------------------------------------------------------------|
| `ENCODE` | Validates the token before it is encoded.                   |
| `DECODE` | Validates the token after it has been verified and decoded. |

Rules can perform different checks depending on the mode.

For example:
- During encoding, rules validate claim relationships.
- During decoding, rules validate the token against the current time.

#### Constant-Time Comparisons
When writing custom rules that compare sensitive token values, comparisons
should be performed using **constant-time equality checks**.

Naïve comparisons such as:
```kotlin
token.subject == "user:42"
```
may leak information through **timing side channels**. Attackers can exploit
small timing differences to gradually guess secret values.

To prevent this, provides constant-time comparison helpers are provided:

| Function                                 | Description                                                                                |
|------------------------------------------|--------------------------------------------------------------------------------------------|
| `ByteArray.constantTimeEquals(expected)` | Compares two byte arrays using constant-time semantics.                                    |
| `String.constantTimeEquals(expected)`    | Compares two strings by converting them to byte arrays and using constant-time comparison. |

Example usage inside a custom rule:
```kotlin
rules {
    customRules += CustomRule { token, mode, _ ->
        val tier = token.claims["tier"]?.asType<String>() ?: return@CustomRule

        if (!tier.constantTimeEquals("premium")) {
            throw RuleValidationException("premium tier required", "tier", token)
        }
    }
}
```

To preserve constant-time behavior, the user-supplied value must be the
receiver of the comparison:
```kotlin
// Correct
userInput.constantTimeEquals(expectedValue)

// Incorrect
expectedValue.constantTimeEquals(userInput)
```
*This ensures the function performs the same amount of work regardless of
whether the values match.*

### Reusing Rule Sets
Rules can be defined independently of a `TokenService` and reused across
multiple services.

The top-level `rules {}` function creates a reusable `Rules` instance:

```kotlin
val authRules = rules {
    issuedBy = IssuedBy("auth-service")
    forAudience = ForAudience("payments-api")
    issuedInPast = IssuedInPast()
    notExpired = NotExpired()
}
```

This ruleset can then be shared by multiple token services:
```kotlin
val serviceA = tokenService(Version.V4, Purpose.Public { _ -> keyPair }) {
    rules(authRules)
}

val serviceB = tokenService(Version.V4, Purpose.Local { _ -> key }) {
    rules(authRules)
}
```

This is useful when the same validation policy is applied across multiple
services or environments.

#### Extending Existing Rules
An existing ruleset can also be extended using the builder DSL:
```kotlin
val adminRules = rules(authRules) {
    subject = Subject("admin")
}
```
This creates a new Rules instance that includes all rules from `authRules` plus
any additional rules defined in the new block.
