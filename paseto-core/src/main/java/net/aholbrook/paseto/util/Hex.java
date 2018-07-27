package net.aholbrook.paseto.util;

import javax.xml.bind.DatatypeConverter;

public class Hex {
	public static byte[] decode(String s) {
		return DatatypeConverter.parseHexBinary(s);
	}
}
