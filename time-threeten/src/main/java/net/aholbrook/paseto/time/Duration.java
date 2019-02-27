package net.aholbrook.paseto.time;

public class Duration {
	private final org.threeten.bp.Duration duration;

	private Duration(org.threeten.bp.Duration duration) {
		this.duration = duration;
	}

	org.threeten.bp.Duration raw() {
		return duration;
	}

	public static Duration ofSeconds(long l) {
		return new Duration(org.threeten.bp.Duration.ofSeconds(l));
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		Duration that = (Duration) o;
		return duration.equals(that.duration);
	}

	@Override
	public int hashCode() {
		return duration.hashCode();
	}

	@Override
	public String toString() {
		return duration.toString();
	}
}
