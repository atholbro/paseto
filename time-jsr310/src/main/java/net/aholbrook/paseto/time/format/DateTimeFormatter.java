package net.aholbrook.paseto.time.format;

public class DateTimeFormatter {
	private final java.time.format.DateTimeFormatter dateTimeFormatter;

	public DateTimeFormatter(java.time.format.DateTimeFormatter dateTimeFormatter) {
		this.dateTimeFormatter = dateTimeFormatter;
	}

	public static DateTimeFormatter ofPattern(String s) {
		return new DateTimeFormatter(java.time.format.DateTimeFormatter.ofPattern(s));
	}

	public java.time.format.DateTimeFormatter raw() {
		return dateTimeFormatter;
	}


}
