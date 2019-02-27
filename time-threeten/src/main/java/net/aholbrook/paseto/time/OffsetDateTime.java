package net.aholbrook.paseto.time;

import net.aholbrook.paseto.time.temporal.ChronoUnit;

public class OffsetDateTime {
	private final org.threeten.bp.OffsetDateTime offsetDateTime;

	public OffsetDateTime(org.threeten.bp.OffsetDateTime offsetDateTime) {
		this.offsetDateTime = offsetDateTime;
	}

	public org.threeten.bp.OffsetDateTime raw() {
		return offsetDateTime;
	}

	public static OffsetDateTime now(Clock systemUTC) {
		return new OffsetDateTime(org.threeten.bp.OffsetDateTime.now(systemUTC.raw()));
	}

	public OffsetDateTime truncatedTo(ChronoUnit seconds) {
		return new OffsetDateTime(offsetDateTime.truncatedTo(seconds.raw()));
	}

	public OffsetDateTime plus(Duration d) {
		return new OffsetDateTime(offsetDateTime.plus(d.raw()));
	}

	public OffsetDateTime minus(Duration d) {
		return new OffsetDateTime(offsetDateTime.minus(d.raw()));
	}

	public boolean isBefore(OffsetDateTime time) {
		return offsetDateTime.isBefore(time.raw());
	}

	public boolean isAfter(OffsetDateTime time) {
		return offsetDateTime.isAfter(time.raw());
	}

	public OffsetDateTime plusSeconds(int l) {
		return new OffsetDateTime(offsetDateTime.plusSeconds(l));
	}

	public OffsetDateTime minusSeconds(long l) {
		return new OffsetDateTime(offsetDateTime.minusSeconds(l));
	}

	public long toEpochSecond() {
		return offsetDateTime.toEpochSecond();
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		OffsetDateTime that = (OffsetDateTime) o;
		return offsetDateTime.equals(that.offsetDateTime);
	}

	@Override
	public int hashCode() {
		return offsetDateTime.hashCode();
	}

	@Override
	public String toString() {
		return offsetDateTime.toString();
	}

	public static OffsetDateTime ofEpochSecond(long l) {
		return new OffsetDateTime(org.threeten.bp.OffsetDateTime.ofInstant(org.threeten.bp.Instant.ofEpochSecond(l),
				org.threeten.bp.ZoneId.of("UTC")));
	}

	public OffsetDateTime plusDays(long l) {
		return new OffsetDateTime(offsetDateTime.plusDays(l));
	}
}
