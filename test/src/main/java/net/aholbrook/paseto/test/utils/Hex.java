package net.aholbrook.paseto.test.utils;

import javax.xml.bind.DatatypeConverter;

public class Hex {
	public static byte[] decode(String s) {
		return DatatypeConverter.parseHexBinary(s);
	}
}
