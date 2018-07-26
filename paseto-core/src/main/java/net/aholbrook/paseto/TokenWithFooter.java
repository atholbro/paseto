package net.aholbrook.paseto;

import java.util.Objects;

public class TokenWithFooter<_TokenType, _Footer> {
	private final _TokenType token;
	private final _Footer footer;

	public TokenWithFooter(_TokenType token, _Footer footer) {
		this.token = token;
		this.footer = footer;
	}

	public _TokenType getToken() {
		return token;
	}

	public _Footer getFooter() {
		return footer;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		TokenWithFooter<?, ?> that = (TokenWithFooter<?, ?>) o;
		return Objects.equals(token, that.token) &&
				Objects.equals(footer, that.footer);
	}

	@Override
	public int hashCode() {

		return Objects.hash(token, footer);
	}
}
