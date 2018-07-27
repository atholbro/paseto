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

package net.aholbrook.paseto.meta;

import net.aholbrook.paseto.PasetoV1;
import net.aholbrook.paseto.PasetoV2;
import net.aholbrook.paseto.crypto.v1.bc.BouncyCastleV1CryptoProvider;
import net.aholbrook.paseto.crypto.v2.libsodium.LibSodiumV2CryptoProvider;
import net.aholbrook.paseto.encoding.json.jackson.JacksonJsonProvider;
import net.aholbrook.paseto.service.LocalTokenService;
import net.aholbrook.paseto.service.PublicTokenService;
import net.aholbrook.paseto.service.Token;

public class PasetoBuilders {
	private PasetoBuilders() {}

	public static class V1 {
		private V1() {}

		public static PasetoV1.Builder paseto() {
			return new PasetoV1.Builder(new JacksonJsonProvider(), new BouncyCastleV1CryptoProvider());
		}

		public static <_TokenType extends Token> LocalTokenService.Builder<_TokenType> localService(
				LocalTokenService.KeyProvider keyProvider, Class<_TokenType> tokenClass) {
			PasetoV1.Builder paseto = paseto();
			return localService(paseto, keyProvider, tokenClass);
		}

		public static <_TokenType extends Token> LocalTokenService.Builder<_TokenType> localService(
				PasetoV1.Builder paseto, LocalTokenService.KeyProvider keyProvider,
				Class<_TokenType> tokenClass) {
			return new LocalTokenService.Builder<>(paseto.build(), tokenClass, keyProvider);
		}

		public static <_TokenType extends Token> PublicTokenService.Builder<_TokenType> publicService(
				PublicTokenService.KeyProvider keyProvider, Class<_TokenType> tokenClass) {
			PasetoV1.Builder paseto = paseto();
			return publicService(paseto, keyProvider, tokenClass);
		}

		public static <_TokenType extends Token> PublicTokenService.Builder<_TokenType> publicService(
				PasetoV1.Builder paseto, PublicTokenService.KeyProvider keyProvider,
				Class<_TokenType> tokenClass) {
			return new PublicTokenService.Builder<>(paseto.build(), tokenClass, keyProvider);
		}
	}

	public static class V2 {
		private V2() {}

		public static PasetoV2.Builder paseto() {
			return new PasetoV2.Builder(new JacksonJsonProvider(), new LibSodiumV2CryptoProvider());
		}

		public static <_TokenType extends Token> LocalTokenService.Builder<_TokenType> localService(
				LocalTokenService.KeyProvider keyProvider, Class<_TokenType> tokenClass) {
			PasetoV2.Builder paseto = paseto();
			return localService(paseto, keyProvider, tokenClass);
		}

		public static <_TokenType extends Token> LocalTokenService.Builder<_TokenType> localService(
				PasetoV2.Builder paseto, LocalTokenService.KeyProvider keyProvider,
				Class<_TokenType> tokenClass) {
			return new LocalTokenService.Builder<>(paseto.build(), tokenClass, keyProvider);
		}

		public static <_TokenType extends Token> PublicTokenService.Builder<_TokenType> publicService(
				PublicTokenService.KeyProvider keyProvider,
				Class<_TokenType> tokenClass) {
			PasetoV2.Builder paseto = paseto();
			return publicService(paseto, keyProvider, tokenClass);
		}

		public static <_TokenType extends Token> PublicTokenService.Builder<_TokenType> publicService(
				PasetoV2.Builder paseto, PublicTokenService.KeyProvider keyProvider,
				Class<_TokenType> tokenClass) {
			return new PublicTokenService.Builder<>(paseto.build(), tokenClass, keyProvider);
		}
	}
}
