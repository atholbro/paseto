package net.aholbrook.paseto.test;

import javax.xml.bind.DatatypeConverter;

public class Hex {
	public static byte[] decode(String s) {
		return DatatypeConverter.parseHexBinary(s);
	}
}
