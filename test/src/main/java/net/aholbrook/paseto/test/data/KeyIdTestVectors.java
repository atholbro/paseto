package net.aholbrook.paseto.test.data;

import net.aholbrook.paseto.service.KeyId;

import java.util.Objects;

public class KeyIdTestVectors {
	public final static KeyId KEY_ID_1 = new KeyId()
			.setKeyId("stored-in-the-footer");
	public final static String KEY_ID_1_STRING = "{\"kid\":\"stored-in-the-footer\"}";
	public final static KeyId KEY_ID_2 = new KeyId()
			.setKeyId("UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo");
	public final static String KEY_ID_2_STRING = "{\"kid\":\"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo\"}";

	public final static Footer KEY_ID_FOOTER = (Footer) new Footer()
			.setField("testing")
			.setKeyId("UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo");
	public final static String KEY_ID_FOOTER_STRING = "{\"field\":\"testing\",\"kid\":\"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJ"
			+ "cdT3zdR65YZxo\"}";

	public static class Footer extends KeyId {
		private String field;

		public String getField() {
			return field;
		}

		public Footer setField(String field) {
			this.field = field;
			return this;
		}

		@Override
		public boolean equals(Object o) {
			if (this == o) return true;
			if (o == null || getClass() != o.getClass()) return false;
			if (!super.equals(o)) return false;
			Footer footer = (Footer) o;
			return Objects.equals(field, footer.field);
		}

		@Override
		public int hashCode() {
			return Objects.hash(super.hashCode(), field);
		}

		@Override
		public String toString() {
			return "Footer{"
					+ "field='" + field + '\''
					+ ", keyId='" + super.toString() + '\''
					+ '}';
		}
	}
}
