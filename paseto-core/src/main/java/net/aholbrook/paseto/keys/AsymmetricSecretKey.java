package net.aholbrook.paseto.keys;

import net.aholbrook.paseto.Version;
import net.aholbrook.paseto.exception.KeyLengthException;

public final class AsymmetricSecretKey extends Key {
	public AsymmetricSecretKey(byte[] material, Version version) {
		super(material, version);

        if (version == Version.V2) {
            if (material.length != 64) {
                throw new KeyLengthException(64, material.length);
            }
        }
	}
}
