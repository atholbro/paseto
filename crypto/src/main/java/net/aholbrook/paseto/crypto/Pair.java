package net.aholbrook.paseto.crypto;

import java.util.Objects;

public class Pair<A, B> {
	public final A a;
	public final B b;

	public Pair(A a, B b) {
		this.a = a;
		this.b = b;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		Pair<?, ?> pair = (Pair<?, ?>) o;
		return a.equals(pair.a) &&
				b.equals(pair.b);
	}

	@Override
	public int hashCode() {
		return Objects.hash(a, b);
	}
}
