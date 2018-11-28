package net.aholbrook.paseto.util;

import org.apache.commons.codec.DecoderException;

public class Hex {
	public static byte[] decode(String s) {
		try {
			return org.apache.commons.codec.binary.Hex.decodeHex(s.toCharArray());
		} catch (DecoderException e) {
			e.printStackTrace();
		}
        return new byte[0];
	}
}
