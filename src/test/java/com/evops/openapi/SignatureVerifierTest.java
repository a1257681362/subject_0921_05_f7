package com.evops.openapi;

import com.evops.openapi.sign.SignatureVerifier;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 签名规范串与 HMAC 计算的纯单元测试：
 * 参数排序、同名多值、RFC3986 编码、发送顺序无关、固定 HMAC 向量、常量时间比较。
 */
class SignatureVerifierTest {

    private final SignatureVerifier verifier = new SignatureVerifier();

    @Test
    void canonical_query_sorts_by_key_then_value() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/open/api/orders");
        request.addParameter("b", "2");
        request.addParameter("a", "1");
        request.addParameter("a", "0"); // 同名第二值，按 value 排前
        assertEquals("a=0&a=1&b=2", verifier.canonicalQuery(request));
    }

    @Test
    void canonical_query_rfc3986_encodes_space_and_chinese() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/open/api/orders");
        request.addParameter("name", "张 三");
        // 张=E5 BC A0，空格=%20，三=E4 B8 89
        assertEquals("name=%E5%BC%A0%20%E4%B8%89", verifier.canonicalQuery(request));
    }

    @Test
    void canonical_query_empty_when_no_params() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/open/api/orders/by-no/O-1");
        assertEquals("", verifier.canonicalQuery(request));
    }

    @Test
    void canonical_query_is_order_independent() {
        MockHttpServletRequest first = new MockHttpServletRequest("GET", "/x");
        first.addParameter("status", "READY");
        first.addParameter("storeCode", "S01");

        MockHttpServletRequest second = new MockHttpServletRequest("GET", "/x");
        second.addParameter("storeCode", "S01");
        second.addParameter("status", "READY");

        assertEquals(verifier.canonicalQuery(first), verifier.canonicalQuery(second));
        assertEquals("status=READY&storeCode=S01", verifier.canonicalQuery(first));
    }

    @Test
    void hmac_sha256_matches_fixed_vectors() {
        String stringToSign = verifier.buildStringToSign(
                "GET", "/open/api/orders", "1759000000000", "nonce12345", "status=READY");
        assertEquals("9772ff87e2ad47fb40b9b59cbd40b80e546952fc7179d159cc0797d412e6b57c",
                verifier.hmacSha256Hex(stringToSign, "test-secret"));
        // 公开已知向量：HMAC-SHA256(key="key", msg="abc")
        assertEquals("9c196e32dc0175f86f4b1cb89289d6619de6bee699e4c378e68309ed97a1a6ab",
                verifier.hmacSha256Hex("abc", "key"));
    }

    @Test
    void build_string_to_sign_uses_newline_join_with_trailing_empty_query() {
        assertEquals("GET\n/p\n100\nn1\n", verifier.buildStringToSign("GET", "/p", "100", "n1", ""));
        assertEquals("GET\n/p\n100\nn1\na=1",
                verifier.buildStringToSign("GET", "/p", "100", "n1", "a=1"));
    }

    @Test
    void matches_is_constant_time_and_null_safe() {
        String sig = verifier.hmacSha256Hex("payload", "secret");
        assertTrue(verifier.matches(sig, sig));
        assertFalse(verifier.matches(sig, sig + "x"));
        assertFalse(verifier.matches(sig, sig.replace('a', 'b')));
        assertFalse(verifier.matches(null, sig));
        assertFalse(verifier.matches(sig, null));
    }
}
