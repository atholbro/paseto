package net.aholbrook.paseto.test;

import net.aholbrook.paseto.crypto.KeyPair;
import net.aholbrook.paseto.test.data.RfcTestVectors;
import org.junit.Assert;
import org.junit.Test;

public class KeyPairTest {
	@Test
	public void keyPair_equals() {
		KeyPair kp1 = new KeyPair(RfcTestVectors.RFC_TEST_RSA_PRIVATE_KEY, RfcTestVectors.RFC_TEST_RSA_PUBLIC_KEY);
		KeyPair kp2 = new KeyPair(RfcTestVectors.RFC_TEST_RSA_PRIVATE_KEY, RfcTestVectors.RFC_TEST_RSA_PUBLIC_KEY);
		Assert.assertEquals(kp1, kp1);
		Assert.assertEquals(kp1, kp2);
		Assert.assertEquals(kp1.hashCode(), kp2.hashCode());
	}

	@Test
	public void keyPair_notEquals() {
		KeyPair kp1 = new KeyPair(RfcTestVectors.RFC_TEST_RSA_PRIVATE_KEY, RfcTestVectors.RFC_TEST_RSA_PUBLIC_KEY);
		KeyPair kp2 = new KeyPair(RfcTestVectors.RFC_TEST_SK, RfcTestVectors.RFC_TEST_PK);
		KeyPair kp3 = new KeyPair(RfcTestVectors.RFC_TEST_RSA_PRIVATE_KEY, RfcTestVectors.RFC_TEST_PK);
		Assert.assertNotEquals(kp1, new Object());
		Assert.assertEquals(false, kp1.equals(null));
		Assert.assertEquals(false, kp1.equals(1));
		Assert.assertNotEquals(kp1, kp2);
		Assert.assertNotEquals(kp1.hashCode(), kp2.hashCode());
		Assert.assertNotEquals(kp1, kp3);
		Assert.assertNotEquals(kp1.hashCode(), kp3.hashCode());
	}
}
