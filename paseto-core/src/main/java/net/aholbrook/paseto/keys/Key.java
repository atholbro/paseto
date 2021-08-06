package net.aholbrook.paseto.keys;

import net.aholbrook.paseto.Version;
import net.aholbrook.paseto.exception.KeyVersionException;

import java.util.Arrays;
import java.util.Objects;

public abstract class Key {
	protected final byte[] material;
	protected final Version version;

	protected Key(byte[] material, Version version) {
		if (material == null) { throw new NullPointerException("Null key material."); }
		if (version == null) { throw new NullPointerException("Null key version."); }

		this.material = material;
		this.version = version;
	}

	public final void verifyKey(Version version) {
		if (version == null) { throw new NullPointerException("version is required."); }
		if (this.version != version) { throw new KeyVersionException(version, this.version); }
	}

	public final byte[] getMaterial() {
		return material;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		Key key = (Key) o;
		return Arrays.equals(material, key.material) &&
				version == key.version;
	}

	@Override
	public int hashCode() {
		int result = Objects.hash(version);
		result = 31 * result + Arrays.hashCode(material);
		return result;
	}
}
