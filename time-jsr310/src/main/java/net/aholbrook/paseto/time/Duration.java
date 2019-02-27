package net.aholbrook.paseto.time;

public class Duration {
	private final java.time.Duration duration;

	private Duration(java.time.Duration duration) {
		this.duration = duration;
	}

	public java.time.Duration raw() {
		return duration;
	}

	public static Duration ofSeconds(long l) {
		return new Duration(java.time.Duration.ofSeconds(l));
	}
}
