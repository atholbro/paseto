package net.aholbrook.paseto.time;

public class Clock {
	private final org.threeten.bp.Clock clock;

	private Clock(org.threeten.bp.Clock clock) {
		this.clock = clock;
	}

	org.threeten.bp.Clock raw() {
		return clock;
	}

	public static Clock systemUTC() {
		return new Clock(org.threeten.bp.Clock.systemUTC());
	}
}
