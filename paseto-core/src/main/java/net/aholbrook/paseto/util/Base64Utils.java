package net.aholbrook.paseto.util;

import java.util.Base64;

public class Base64Utils {
    public static byte[] strictBase64UrlDecode(String b64) {
        byte[] decoded = Base64.getUrlDecoder().decode(b64);
        String re = Base64.getUrlEncoder().withoutPadding().encodeToString(decoded);
        if (!re.equals(b64)) {
            return null;
        } else {
            return decoded;
        }
    }
}
