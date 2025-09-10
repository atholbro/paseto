# PASETO: Platform-Agnostic Security Tokens
[![Build Status](https://travis-ci.org/atholbro/paseto.svg?branch=master)](https://travis-ci.org/atholbro/paseto)
[![codecov](https://codecov.io/gh/atholbro/paseto/branch/master/graph/badge.svg)](https://codecov.io/gh/atholbro/paseto)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
 
A Java Implementation of Platform-Agnostic Security Tokens - https://paseto.io

Paseto is everything you love about JOSE (JWT, JWE, JWS) without any of the
[many design deficits that plague the JOSE standards](https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid).

# Contents
* [What is Paseto?](#what-is-paseto)
  * [Key Differences between Paseto and JWT](#key-differences-between-paseto-and-jwt)
  * [Supported Paseto Features](#supported-paseto-features)
  * [Motivation](#motivation)
* [Installation](#installation)
  * [Gradle](#gradle)
  * [Maven](#maven)
* [Usage](#usage)
  * [A note on the available APIs](#a-note-on-the-available-apis)
  * [V1 vs V2](#v1-vs-v2)
  * [JsonToken API](#jsontoken-api)

# What is Paseto?

Paseto (Platform-Agnostic SEcurity TOkens) is a specification and reference implementation
for secure stateless tokens.

## Key Differences between Paseto and JWT

Unlike JSON Web Tokens (JWT), which gives developers more than enough rope with which to
hang themselves, Paseto only allows secure operations. JWT gives you "algorithm agility",
Paseto gives you "versioned protocols". It's incredibly unlikely that you'll be able to
use Paseto in [an insecure way](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries).

> **Caution:** Neither JWT nor Paseto were designed for
> [stateless session management](http://cryto.net/~joepie91/blog/2016/06/13/stop-using-jwt-for-sessions/).
> Paseto is suitable for tamper-proof cookies, but cannot prevent replay attacks
> by itself.

## Supported Paseto Features
| Feature | Supported |
| :-------------: | :-: |
| v1.local | ✓ |
| v1.public | ✓ |
| v2.local | ✓ |
| v2.public | ✓ |
| JsonToken | ✓ |

## Motivation
This library was created to support all Paseto features in a plugable fashion. The JSON, and cryptography code
for V1/V2 are separate libraries, which allows their implementation to be replaced with alternatives. For
example: the default JSON encoding is provided via Jackson, however if you are already using GSON, then you
can provide your own EncodingProvider and call into GSON to encode JSON. At some point an implementation of
the cryptographic primitives required for v2 tokens in pure Java may be provided.

Currently the following providers are available:

|         Name          | Type | Description |
|:---------------------:| :----: | --------------------------------------------------------------------------------------- |
| encoding-jackson-json | EncodingProvider | JSON using Jackson |
|     crypto-v1-bc      | V1CryptoProvider | Cryptography for Paseto V1 Tokens using Bouncy Castle |
|     crypto-v2-bc      | V2CryptoProvider | Cryptography for Paseto V2 Tokens using Bouncy Castle |

_Note: GSON will be officailly supported in the future as an alternative to Jackson._

# Installation
### Gradle

```gradle
dependencies {
	compile 'net.aholbrook.paseto:meta:0.6.1'
}
```

# Usage
### A note on the available APIs
A high level wrapper around raw Paseto tokens is provided and its usage is encouraged. This high level API implements
the Paseto `JsonToken` as described in the RFC. However since JsonToken was just recently made a requirement, other
Paseto implementations provide access to raw Paseto tokens. As such access to the low level Paseto token API is
available and described below should you need to work with raw tokens from another library. Most users should stick
with the offical JsonToken (which this library allows you to extend if needed).

### V1 vs V2
If your curious as to why Paseto has V1 and V2 tokens, you can find more details in the Paseto RFC (section 3)
(https://paseto.io/rfc). Basically version 1 tokens are a compatibility mode for legacy systems where the newer
cryptographic primitives required by version 2 are unavailable. An example might be an Arduino.

All other systems should use the newest version, which is currently version 2. Paseto versions are not backward
compatible, therefore a token created with V1 must be verified with V1 and will fail validation if passed to a
V2 instance.

### Local and Public
Paseto tokens come in two varieties: _local_ and _public_. The following table outlines the differences:

|  Type  | Encrypted | Authentication | Asymmetric |
|--------|:---------:|:--------------:|:----------:|
|  local |     ✓     |        ✓       |            |
| public |           |        ✓       |      ✓     |

Both varieties are protected from modifications (authentication). Local tokens are encrypted, but require the same key for encryption and decryption. Public tokens are not encrypted, meaning that anyone can read their contents, however they can
be verified using a public key. This allows a party to verify a public token without having the ability to create a valid
token.

## JsonToken API
### Getting Started
Lets start with an example of creating a basic Paseto JsonToken. For this example we'll use a local token (encrypted) variant and the latest version (2).
```
byte[] key = Hex.decode("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f");
TokenService<Token> tokenService = PasetoBuilders.V2.localService(() -> key, Token.class)
    .withDefaultValidityPeriod(Duration.ofDays(15).getSeconds())
    .build();

Token token = new Token();
token.setTokenId("example-id"); // A session key, user id, etc.

String encoded = tokenService.encode(token);
```

Lets break down the example step by step:

```byte[] key = Hex.decode("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f");```

To encode a Paseto token, an encryption key is required. Paseto expects your encryption key to be provided as an
array of bytes. For this example we use the provided Hex utility class to decode a byte array from a String of hex
pairs.


```
TokenService<Token> tokenService = PasetoBuilders.V2.localService(() -> key, Token.class)
    .withDefaultValidityPeriod(Duration.ofDays(15).getSeconds())
    .build();
```
Next we create an instance of the Paseto LocalTokenService. The TokenService is the interface to the interface to
high level Paseto API. The minimum requirements to work with local Paseto tokens are the encryption key, and the
type of token. `PasetoBuilders.V2.localService()` returns a builder, which allows you to adjust some of the default
behaviors when encoding/decoding tokens. In this example we set a default validity period, which automatically sets
the token expiration date & time such that the token is valid for the given duration (15 days in this example).

We provide the encryption key via a lambda `() -> key` which simply returns the key variable we defined in the
previous step _(the interface is LocalTokenService.KeyProvider)_. An interface is used here so that the key can be
loaded on demand for each encode/decode operation. We'll cover this in more detail below, but for now just know that
the high level API will call this lambda each time a token is encoded / decoded.

The type of token must also be specified as this library allows you to extend the base Token type to add your own
data fields (provided they don't conflict with the existing fields). Due to this extensibility we have to tell the
TokenService which type of token to instantiate when decoding a token.

We then call `withDefaultValidityPeriod()` on the builder, which allows us to set a default expiration date & time. When
set, the service will automatically set the token issue and expiration fields based off the current time, unless already
set. This reduces the code requirement to create a token, as typically most tokens in an application will have a standard
validity period. If we had excluded the call to `withDefaultValidityPeriod()` then no default would be set, and we'd be
required to set an expiration date & time.

Finally a call to build() is made, which creates an instance of the TokenService.

```
Token token = new Token();
token.setTokenId("example-id"); // Where "example-id" is an entry in a database table.
```
Next we create a new token and set it's ID to "example-id". The token ID resolves to the Paseto jti claim (We call it the
Token ID claim in this library as its easier to deduce it's meaning). The Token ID claim is used to prevent reply attacks
by providing a key to lookup if this token has been previously used. The details of this are left to the application
engineer (like with JWT).

```
String encoded = tokenService.encode(token);
```
The last step is to call encode with the token. Encode returns a String which contains the contents of the token, encrypted
and authenticated with the key provided earlier. Do note, that this token is "salted" such that repeat calls to encode will
produce different ouput, however the contents stored within the token remain the same.

The contents of the token are now protected from tampering, as any change to the token string will invalidate the cryptographic
signature applied. Since this is a "local" token, the contents are also encrypted, so secret details can be passed to the user
but only read by our software.

### Decoding & Verifiying
Now that we've encoded our first Paseto token, lets see how we decrypt the contents and verify that no modifications have been
made.
```
// continuing from the previous example
Token decoded = tokenService.decode(encoded);
```
This example continues from the previous example and immediately decrypts and verifies the token. Typically this will be some
time later, when the client returns the token to our application. The decode() function verifies the integrity of the token and
decrypts its contents. The contents of the token are returned as an object of the same type that was given when encoding the
token.

If the token was modified by the user, or if the token has expired, then an exception of type PasetoException will be thrown
and the contents of the token will not be returned. The exception will contain the reason as to why the token failed to decode.

### Token Footers
If you need to store data in the token which is authenticated but not encrypted, then you can do so using the token footer. The
typical use case for this is picking the encryption key used to sign the token, and a default Footer class (KeyId) is provided
for this purpose. Do note, that you should never store the encryption key in the token footer, the KeyId should be set to an
identifier which describes the key used, not the key itself. For example you could set the KeyId to the date/time that the key
was issued.

You can also store data that you may need to decode before the token is verified by providing your own footer class (or
extending KeyId if you need it's functionality as well). For example you could store the user's first name to give them a
personalized error message if the token fails to validate.

__Data stored in the token footer is never encrypted and the client can easily read this data by Base64 decoding
the token string. The data is protected against tampering so long as you're not using the getFooter() method.__

```
KeyId footer = new KeyId();
footer.setKeyId("1"); // first key we're using
		
encoded = tokenService.encode(token, footer);

```

And that's all there is to setting a token footer, just provide it to the encode() call. Any type is accepted as a footer, it
does not have to be a KeyId. You could provide a basic string, or an object which will be encoded using JSON.

### Decoding with Footers
When decoding a token that has a footer, you have 4 options:
- Pass the expected footer value to the Paseto library.
- Decrypt & Verify the token, and return both the Token and the decoded Footer.
- Peek at the footer.
- Ignore the footer.

We'll look at each one in order:

#### Decode with an expected footer value
Let's say you start out with a basic `Token`, then later extend it to your own `CustomToken` and only want to accept the newer
CustomTokens. One way to approach this is to add the token type as a footer, for this example lets say that footer is the
string "custom". In this case you only want to accept tokens that have their footer set as "custom".

The Paseto library supports this by passing the expected value into the decode function. The footer will be checked before
decoding the token using constant time equals to protect against timing attacks. If the footer present in the token does
not match the given footer, then an exception will be thrown and the `decode()` operation will fail. This allows you to safely
ensure that the footer contents equals a specific value.

```
decoded = tokenService.decode(encoded, footer);
```

_Note that you may run into trouble if using JSON encoding for the footer as the field order may change. With Jackson you can
define the field order by using the @JsonPropertyOrder annotation. Other libraries may not support this._

#### Return the token and the footer
If you need access to the data in the footer beyond ensuring that its equal to an expected value, then you can return the footer
with the decoded token by passing the class of the footer type to the `decodeWithFooter()` method. The Token and Footer are
returned in a Tuple object "TokenWithFooter" which stores both values.

```
TokenWithFooter twf = tokenService.decodeWithFooter(encoded, KeyId.class);
decoded = twf.getToken();
footer = twf.getFooter();
```

#### Peak at the footer
If you need to check the value before decoding the token then you can use the getFooter() method.

```
footer = tokenService.getFooter(encoded, KeyId.class);
```
__No authentication is performed when "peeking" at the footer, and therefore getFooter() should only be used when it
does not matter if the value has been tampered with.__

#### Ignore the footer
If you don't need access to the footer, then you can use the regular `decode()` method which will silently ignore the footer.



