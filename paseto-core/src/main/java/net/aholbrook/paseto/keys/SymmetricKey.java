package net.aholbrook.paseto.keys;

import net.aholbrook.paseto.Version;
import net.aholbrook.paseto.exception.KeyLengthException;

public final class SymmetricKey extends Key {
	public SymmetricKey(byte[] material, Version version) {
		super(material, version);

		if (material.length != 32) {
			throw new KeyLengthException(32,  material.length);
		}
	}
}
