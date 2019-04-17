package net.aholbrook.paseto.test.utils;

import org.apache.commons.codec.DecoderException;

public class Hex {
	public static byte[] decode(String hex) {
		try {
			return org.apache.commons.codec.binary.Hex.decodeHex(hex);
		} catch (DecoderException e) {
			throw new RuntimeException(e);
		}
	}
}
