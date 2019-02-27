package net.aholbrook.paseto.time;

public class Clock {
	private final java.time.Clock clock;

	private Clock(java.time.Clock clock) {
		this.clock = clock;
	}

	public java.time.Clock raw() {
		return clock;
	}

	public static Clock systemUTC() {
		return new Clock(java.time.Clock.systemUTC());
	}
}
