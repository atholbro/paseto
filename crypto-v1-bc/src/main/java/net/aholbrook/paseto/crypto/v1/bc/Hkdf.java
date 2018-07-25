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

package net.aholbrook.paseto.crypto.v1.bc;

import at.favre.lib.crypto.HKDF;
import at.favre.lib.crypto.HkdfMacFactory;
import net.aholbrook.paseto.crypto.v1.HkdfProvider;

public class Hkdf implements HkdfProvider {
	private final HKDF hkdf;

	public Hkdf() {
		hkdf = HKDF.from(new HkdfMacFactory.Default("HmacSHA384"));
	}

	@Override
	public byte[] extractAndExpand(byte[] salt, byte[] inputKeyingMaterial, byte[] info, int outLen) {
		return hkdf.extractAndExpand(salt, inputKeyingMaterial, info, outLen);
	}
}
