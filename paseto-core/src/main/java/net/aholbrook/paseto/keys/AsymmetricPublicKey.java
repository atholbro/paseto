package net.aholbrook.paseto.keys;

import net.aholbrook.paseto.Version;

public final class AsymmetricPublicKey extends Key {
	public AsymmetricPublicKey(byte[] material, Version version) {
		super(material, version);
	}
}
