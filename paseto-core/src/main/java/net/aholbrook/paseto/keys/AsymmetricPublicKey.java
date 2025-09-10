package net.aholbrook.paseto.keys;

import net.aholbrook.paseto.Version;
import net.aholbrook.paseto.exception.KeyLengthException;

public final class AsymmetricPublicKey extends Key {
	public AsymmetricPublicKey(byte[] material, Version version) {
		super(material, version);

        if (version == Version.V2) {
            if (material.length != 32) {
                throw new KeyLengthException(32, material.length);
            }
        }
	}
}
