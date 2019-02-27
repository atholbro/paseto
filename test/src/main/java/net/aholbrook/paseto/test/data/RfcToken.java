package net.aholbrook.paseto.test.data;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import net.aholbrook.paseto.service.Token;

import java.time.OffsetDateTime;
import java.util.Objects;

// only needed for testing as we store the result as a string, so the field order must match
@JsonPropertyOrder({"data", "exp"})
public class RfcToken extends Token {
	private String data;

	public RfcToken() {
	}

	public RfcToken(String data, String exp) {
		this.data = data;
		setExpiration(Token.DATETIME_FORMATTER.parse(exp).toEpochSecond());
	}

	public String getData() {
		return data;
	}

	public void setData(String data) {
		this.data = data;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		if (!super.equals(o)) return false;
		RfcToken rfcToken = (RfcToken) o;
		return Objects.equals(data, rfcToken.data);
	}

	@Override
	public int hashCode() {
		return Objects.hash(super.hashCode(), data);
	}
}
