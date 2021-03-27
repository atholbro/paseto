package net.aholbrook.paseto;

import net.aholbrook.paseto.crypto.KeyPair;
import net.aholbrook.paseto.data.RfcTestVectors;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Key Pair")
public class KeyPairTest {
	@Test
	@DisplayName("Equals returns true when two key pairs are equal.")
	public void keyPair_equals() {
		KeyPair kp1 = new KeyPair(RfcTestVectors.RFC_TEST_RSA_PRIVATE_KEY, RfcTestVectors.RFC_TEST_RSA_PUBLIC_KEY);
		KeyPair kp2 = new KeyPair(RfcTestVectors.RFC_TEST_RSA_PRIVATE_KEY, RfcTestVectors.RFC_TEST_RSA_PUBLIC_KEY);
		Assertions.assertEquals(kp1, kp1);
		Assertions.assertEquals(kp1, kp2);
		Assertions.assertEquals(kp1.hashCode(), kp2.hashCode());
	}

	@Test
	@DisplayName("Equals returns false when two key pairs are different.")
	public void keyPair_notEquals() {
		KeyPair kp1 = new KeyPair(RfcTestVectors.RFC_TEST_RSA_PRIVATE_KEY, RfcTestVectors.RFC_TEST_RSA_PUBLIC_KEY);
		KeyPair kp2 = new KeyPair(RfcTestVectors.RFC_TEST_SK, RfcTestVectors.RFC_TEST_PK);
		KeyPair kp3 = new KeyPair(RfcTestVectors.RFC_TEST_RSA_PRIVATE_KEY, RfcTestVectors.RFC_TEST_PK);
		Assertions.assertNotEquals(kp1, new Object());
		Assertions.assertEquals(false, kp1.equals(null));
		Assertions.assertEquals(false, kp1.equals(1));
		Assertions.assertNotEquals(kp1, kp2);
		Assertions.assertNotEquals(kp1.hashCode(), kp2.hashCode());
		Assertions.assertNotEquals(kp1, kp3);
		Assertions.assertNotEquals(kp1.hashCode(), kp3.hashCode());
	}
}
