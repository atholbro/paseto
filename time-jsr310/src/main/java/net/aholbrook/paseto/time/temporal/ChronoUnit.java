package net.aholbrook.paseto.time.temporal;

public enum ChronoUnit {
	NANOS(java.time.temporal.ChronoUnit.NANOS),
	MICROS(java.time.temporal.ChronoUnit.MICROS),
	MILLIS(java.time.temporal.ChronoUnit.MILLIS),
	SECONDS(java.time.temporal.ChronoUnit.SECONDS),
	MINUTES(java.time.temporal.ChronoUnit.MINUTES),
	HOURS(java.time.temporal.ChronoUnit.HOURS),
	HALF_DAYS(java.time.temporal.ChronoUnit.HALF_DAYS),
	DAYS(java.time.temporal.ChronoUnit.DAYS),
	WEEKS(java.time.temporal.ChronoUnit.WEEKS),
	MONTHS(java.time.temporal.ChronoUnit.MONTHS),
	YEARS(java.time.temporal.ChronoUnit.YEARS),
	DECADES(java.time.temporal.ChronoUnit.DECADES),
	CENTURIES(java.time.temporal.ChronoUnit.CENTURIES),
	MILLENNIA(java.time.temporal.ChronoUnit.MILLENNIA),
	ERAS(java.time.temporal.ChronoUnit.ERAS),
	FOREVER(java.time.temporal.ChronoUnit.FOREVER);

	private final java.time.temporal.ChronoUnit chronoUnit;

	ChronoUnit(java.time.temporal.ChronoUnit chronoUnit) {
		this.chronoUnit = chronoUnit;
	}

	public java.time.temporal.ChronoUnit raw() {
		return chronoUnit;
	}
}
