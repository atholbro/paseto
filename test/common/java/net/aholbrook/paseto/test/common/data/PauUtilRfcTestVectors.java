package net.aholbrook.paseto.test.common.data;

import net.aholbrook.paseto.test.common.utils.Hex;

public class PauUtilRfcTestVectors {
	public final static byte[] PAE_VECTOR_1 = Hex.decode("0000000000000000");
	public final static byte[] PAE_VECTOR_2 = Hex.decode("01000000000000000000000000000000");
	// ends with test
	public final static byte[] PAE_VECTOR_3 = Hex.decode("0100000000000000040000000000000074657374");
}
