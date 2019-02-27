package net.aholbrook.paseto.time.temporal;

public enum ChronoUnit {
	SECONDS(org.threeten.bp.temporal.ChronoUnit.SECONDS);

	private final org.threeten.bp.temporal.ChronoUnit chronoUnit;

	ChronoUnit(org.threeten.bp.temporal.ChronoUnit chronoUnit) {
		this.chronoUnit = chronoUnit;
	}

	public org.threeten.bp.temporal.ChronoUnit raw() {
		return chronoUnit;
	}
}
