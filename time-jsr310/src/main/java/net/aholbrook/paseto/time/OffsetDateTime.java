package net.aholbrook.paseto.time;

import net.aholbrook.paseto.time.temporal.ChronoUnit;

public class OffsetDateTime {
	private final java.time.OffsetDateTime offsetDateTime;

	private OffsetDateTime(java.time.OffsetDateTime offsetDateTime) {
		this.offsetDateTime = offsetDateTime;
	}

	public java.time.OffsetDateTime raw() {
		return offsetDateTime;
	}

	public static OffsetDateTime now(Clock systemUTC) {
		return new OffsetDateTime(java.time.OffsetDateTime.now(systemUTC.raw()));
	}

	public OffsetDateTime truncatedTo(ChronoUnit seconds) {
		return new OffsetDateTime(offsetDateTime.truncatedTo(seconds.raw()));
	}

	public OffsetDateTime plus(Duration defaultValidityPeriod) {
		return new OffsetDateTime(offsetDateTime.plus(defaultValidityPeriod.raw()));
	}
}
