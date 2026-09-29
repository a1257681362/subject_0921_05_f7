package com.evops.openapi.sign;

import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * HMAC-SHA256 签名的构造与校验（无状态纯逻辑，便于单测）。
 *
 * 待签名串（\n 为换行符）：
 *   METHOD + "\n" + requestURI(不含 query) + "\n" + timestamp + "\n" + nonce + "\n" + canonicalQuery
 * canonicalQuery：全部 query 参数按 key 字典序、同 key 按 value 字典序排序，
 * 每段 RFC3986 百分号编码后以 k=v&amp;k=v 拼接；无参数为空串。
 * 故调用方参数发送顺序不影响验签，单个参数被篡改即签名不符。对外仅开放 GET，body 不参与签名。
 */
@Component
public class SignatureVerifier {

    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    /** 排序 + 编码后的 query 规范串 */
    public String canonicalQuery(HttpServletRequest request) {
        Map<String, String[]> raw = request.getParameterMap();
        if (raw == null || raw.isEmpty()) {
            return "";
        }
        List<String[]> pairs = new ArrayList<>();
        for (Map.Entry<String, String[]> entry : raw.entrySet()) {
            String key = entry.getKey() == null ? "" : entry.getKey();
            String[] values = entry.getValue();
            if (values == null || values.length == 0) {
                pairs.add(new String[]{key, ""});
                continue;
            }
            for (String value : values) {
                pairs.add(new String[]{key, value == null ? "" : value});
            }
        }
        // 先按 key 再按 value 字典序，保证双方实现一致
        Collections.sort(pairs, (a, b) -> {
            int byKey = a[0].compareTo(b[0]);
            return byKey != 0 ? byKey : a[1].compareTo(b[1]);
        });
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < pairs.size(); i++) {
            if (i > 0) {
                sb.append('&');
            }
            sb.append(rfc3986Encode(pairs.get(i)[0])).append('=').append(rfc3986Encode(pairs.get(i)[1]));
        }
        return sb.toString();
    }

    public String buildStringToSign(String method, String requestUri, String timestamp,
                                    String nonce, String canonicalQuery) {
        return method + "\n" + requestUri + "\n" + timestamp + "\n" + nonce + "\n"
                + (canonicalQuery == null ? "" : canonicalQuery);
    }

    public String hmacSha256Hex(String content, String secret) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM));
            return toHex(mac.doFinal(content.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception ex) {
            // HmacSHA256 为 JDK 必备算法、UTF-8 必备字符集，理论不可达
            throw new IllegalStateException("HMAC-SHA256 计算失败", ex);
        }
    }

    /**
     * 常量时间比较，避免按字节短路泄露签名前缀信息。长度不同也走比较路径。
     */
    public boolean matches(String expectedHex, String providedHex) {
        if (expectedHex == null || providedHex == null) {
            return false;
        }
        return MessageDigest.isEqual(
                expectedHex.getBytes(StandardCharsets.UTF_8),
                providedHex.getBytes(StandardCharsets.UTF_8));
    }

    private static String toHex(byte[] bytes) {
        char[] out = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            out[i * 2] = HEX[v >>> 4];
            out[i * 2 + 1] = HEX[v & 0x0F];
        }
        return new String(out);
    }

    /**
     * RFC3986 百分号编码：不编码 unreserved（A-Za-z0-9-_.~），其余字节按 UTF-8 百分号大写。
     * 百分号统一大写是 RFC3986 的规范化惯例（curl/openssl 调用方一致），
     * 注意区别于 HMAC 摘要本身的小写 hex；参数先经容器解码再由此重编码，双方结果一致。
     * URLEncoder 把空格编成 '+'，这里替换为 %20。
     */
    private static String rfc3986Encode(String value) {
        StringBuilder sb = new StringBuilder();
        for (byte b : value.getBytes(StandardCharsets.UTF_8)) {
            int c = b & 0xFF;
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '_' || c == '.' || c == '~') {
                sb.append((char) c);
            } else if (c == ' ') {
                sb.append("%20");
            } else {
                sb.append('%').append(Character.toUpperCase(HEX[c >>> 4]))
                        .append(Character.toUpperCase(HEX[c & 0x0F]));
            }
        }
        return sb.toString();
    }
}
