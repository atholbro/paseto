package net.aholbrook.paseto.time.temporal;

public enum ChronoUnit {
	SECONDS(java.time.temporal.ChronoUnit.SECONDS);

	private final java.time.temporal.ChronoUnit chronoUnit;

	ChronoUnit(java.time.temporal.ChronoUnit chronoUnit) {
		this.chronoUnit = chronoUnit;
	}

	public java.time.temporal.ChronoUnit raw() {
		return chronoUnit;
	}
}
