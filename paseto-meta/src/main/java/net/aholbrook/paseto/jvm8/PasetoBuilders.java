/*
Copyright 2018 Andrew Holbrook

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

package net.aholbrook.paseto.jvm8;

import net.aholbrook.paseto.Paseto;
import net.aholbrook.paseto.base64.jvm8.Jdk8Base64Provider;
import net.aholbrook.paseto.crypto.v1.bc.JvmV1CryptoProvider;
import net.aholbrook.paseto.crypto.v2.libsodium.LibSodiumV2CryptoProvider;
import net.aholbrook.paseto.encoding.json.jackson.JacksonJsonProvider;

public class PasetoBuilders {
	public static <_Payload> Paseto.Builder<_Payload> v1() {
		return new Paseto.Builder<_Payload>()
				.v1(new JvmV1CryptoProvider())
				.withBase64(new Jdk8Base64Provider())
				.withJson(new JacksonJsonProvider());
	}

	public static <_Payload> Paseto.Builder<_Payload> v2() {
		return new Paseto.Builder<_Payload>()
				.v2(new LibSodiumV2CryptoProvider())
				.withBase64(new Jdk8Base64Provider())
				.withJson(new JacksonJsonProvider());
	}
}
