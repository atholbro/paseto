package net.aholbrook.paseto.keys;

import net.aholbrook.paseto.Version;

public final class SymmetricKey extends Key {
	public SymmetricKey(byte[] material, Version version) {
		super(material, version);
	}
}
