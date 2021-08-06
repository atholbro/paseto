package net.aholbrook.paseto.keys;

import net.aholbrook.paseto.Version;

public final class AsymmetricSecretKey extends Key {
	public AsymmetricSecretKey(byte[] material, Version version) {
		super(material, version);
	}
}
