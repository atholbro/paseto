package net.aholbrook.paseto.time.format;

import net.aholbrook.paseto.time.OffsetDateTime;

public class DateTimeFormatter {
	private final org.threeten.bp.format.DateTimeFormatter dateTimeFormatter;

	private DateTimeFormatter(org.threeten.bp.format.DateTimeFormatter dateTimeFormatter) {
		this.dateTimeFormatter = dateTimeFormatter;
	}

	public static DateTimeFormatter ofPattern(String s) {
		return new DateTimeFormatter(org.threeten.bp.format.DateTimeFormatter.ofPattern(s));
	}

	public org.threeten.bp.format.DateTimeFormatter raw() {
		return dateTimeFormatter;
	}


	public OffsetDateTime parse(CharSequence charSequence) {
		return new OffsetDateTime(dateTimeFormatter.parse(charSequence, org.threeten.bp.OffsetDateTime::from));
	}

	public String format(OffsetDateTime value) {
		return dateTimeFormatter.format(value.raw());
	}
}
