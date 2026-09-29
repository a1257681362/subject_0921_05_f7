package com.evops.openapi;

import com.evops.openapi.maintenance.OpenApiNonceMaintenance;
import org.apache.shiro.spring.web.config.DefaultShiroFilterChainDefinition;
import org.apache.shiro.spring.web.config.ShiroFilterChainDefinition;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

import javax.annotation.Resource;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 对外开放加工单查询的 HMAC 安全机制集成测试：
 * 参数排序签名、参数乱序、篡改/缺头/未知调用方、15 分钟时间窗、nonce 重放、
 * 过期清理，以及失败只回专用码不暴露细节。
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(OpenApiSignatureIntegrationTest.TestShiroBypass.class)
class OpenApiSignatureIntegrationTest {

    @TestConfiguration
    static class TestShiroBypass {
        @Bean
        ShiroFilterChainDefinition shiroFilterChainDefinition() {
            DefaultShiroFilterChainDefinition chain = new DefaultShiroFilterChainDefinition();
            chain.addPathDefinition("/**", "anon");
            return chain;
        }
    }

    private static final String ACCESS_KEY = "test-ak";
    private static final String SECRET = "test-secret";
    private static final String BASE = "/open/api/orders";

    @Resource
    private org.springframework.test.web.servlet.MockMvc mockMvc;
    @Resource
    private JdbcTemplate jdbcTemplate;
    @Resource
    private OpenApiNonceMaintenance nonceMaintenance;

    private final AtomicLong nonceSeq = new AtomicLong();

    @BeforeEach
    void cleanNonce() {
        jdbcTemplate.update("DELETE FROM t_open_api_nonce");
    }

    // ---------------- 正常签名 ----------------

    @Test
    void valid_signature_passes() throws Exception {
        mockMvc.perform(signedGet(BASE + "?status=CREATED&storeCode=S001", nowMillis(), freshNonce()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value("OK"));
        assertEquals(1L, nonceCount());
    }

    @Test
    void query_params_in_any_order_sign_sorted() throws Exception {
        // 请求行里参数顺序与字典序相反，签名仍按排序后的参数计算 → 通过
        SignedRequest req = sign(BASE + "?storeCode=S001&status=CREATED", nowMillis(), freshNonce());
        mockMvc.perform(get(req.uri)
                        .header("X-Access-Key", ACCESS_KEY)
                        .header("X-Timestamp", String.valueOf(req.timestamp))
                        .header("X-Nonce", req.nonce)
                        .header("X-Signature", req.signature))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value("OK"));
    }

    @Test
    void signature_is_over_url_decoded_values() throws Exception {
        // 含空格的值请求行编码为 %20，签名按解码后的原文计算 → 通过。
        // 用 URI 而非字符串构造：字符串模板会把字面 % 再编码一次（%20 → %2520），测不出真实解码
        long ts = nowMillis();
        String nonce = freshNonce();
        SignedRequest req = sign(BASE + "?storeCode=S%2001", ts, nonce);
        mockMvc.perform(get(new java.net.URI(req.uri))
                        .header("X-Access-Key", ACCESS_KEY)
                        .header("X-Timestamp", String.valueOf(req.timestamp))
                        .header("X-Nonce", req.nonce)
                        .header("X-Signature", req.signature))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value("OK"));
    }

    @Test
    void signed_request_reaches_business_logic() throws Exception {
        // 不存在的单号：签名通过后才进入业务，返回业务码而非鉴权码
        SignedRequest req = sign(BASE + "/by-no/NO-SUCH-ORDER", nowMillis(), freshNonce());
        mockMvc.perform(get(req.uri)
                        .header("X-Access-Key", ACCESS_KEY)
                        .header("X-Timestamp", String.valueOf(req.timestamp))
                        .header("X-Nonce", req.nonce)
                        .header("X-Signature", req.signature))
                .andExpect(jsonPath("$.code").value("ORDER_NOT_FOUND"));
    }

    // ---------------- 拒绝类：全部 OPEN_SIGN_INVALID，不带细节 ----------------

    @Test
    void missing_signature_header_rejected() throws Exception {
        mockMvc.perform(get(BASE).header("X-Access-Key", ACCESS_KEY)
                        .header("X-Timestamp", String.valueOf(nowMillis())).header("X-Nonce", freshNonce()))
                .andExpect(jsonPath("$.code").value("OPEN_SIGN_INVALID"))
                .andExpect(jsonPath("$.message").value("请求签名校验未通过"));
    }

    @Test
    void unknown_access_key_rejected() throws Exception {
        SignedRequest req = sign(BASE, nowMillis(), freshNonce(), ACCESS_KEY, SECRET);
        mockMvc.perform(get(req.uri)
                        .header("X-Access-Key", "stranger-ak")
                        .header("X-Timestamp", String.valueOf(req.timestamp))
                        .header("X-Nonce", req.nonce)
                        .header("X-Signature", req.signature))
                .andExpect(jsonPath("$.code").value("OPEN_SIGN_INVALID"))
                .andExpect(jsonPath("$.message").value("请求签名校验未通过"));
    }

    @Test
    void tampered_query_param_rejected() throws Exception {
        SignedRequest req = sign(BASE + "?storeCode=S001", nowMillis(), freshNonce());
        // 改参数值不换签名
        mockMvc.perform(get(BASE + "?storeCode=S999")
                        .header("X-Access-Key", ACCESS_KEY)
                        .header("X-Timestamp", String.valueOf(req.timestamp))
                        .header("X-Nonce", req.nonce)
                        .header("X-Signature", req.signature))
                .andExpect(jsonPath("$.code").value("OPEN_SIGN_INVALID"))
                .andExpect(jsonPath("$.message").value("请求签名校验未通过"));
    }

    @Test
    void wrong_signature_rejected() throws Exception {
        // 手建请求：signedGet 已带签名头，再 .header() 追加同名头时服务端取第一个（仍有效），测不出篡改
        SignedRequest req = sign(BASE, nowMillis(), freshNonce());
        mockMvc.perform(get(req.uri)
                        .header("X-Access-Key", ACCESS_KEY)
                        .header("X-Timestamp", String.valueOf(req.timestamp))
                        .header("X-Nonce", req.nonce)
                        .header("X-Signature", "deadbeef"))
                .andExpect(jsonPath("$.code").value("OPEN_SIGN_INVALID"));
    }

    @Test
    void timestamp_beyond_15_minutes_rejected() throws Exception {
        long tooOld = nowMillis() - 16 * 60_000L;
        mockMvc.perform(signedGet(BASE, tooOld, freshNonce()))
                .andExpect(jsonPath("$.code").value("OPEN_SIGN_INVALID"));

        long tooNew = nowMillis() + 16 * 60_000L;
        mockMvc.perform(signedGet(BASE, tooNew, freshNonce()))
                .andExpect(jsonPath("$.code").value("OPEN_SIGN_INVALID"));
    }

    @Test
    void timestamp_within_window_passes() throws Exception {
        long fourteenMinAgo = nowMillis() - 14 * 60_000L;
        mockMvc.perform(signedGet(BASE, fourteenMinAgo, freshNonce()))
                .andExpect(jsonPath("$.code").value("OK"));
    }

    // ---------------- nonce 防重放 ----------------

    @Test
    void same_nonce_replayed_is_rejected() throws Exception {
        String nonce = freshNonce();
        long ts = nowMillis();

        mockMvc.perform(signedGet(BASE, ts, nonce))
                .andExpect(jsonPath("$.code").value("OK"));
        // 同 accessKey + nonce 原样重放：直接拒绝，不进入业务
        mockMvc.perform(signedGet(BASE, ts, nonce))
                .andExpect(jsonPath("$.code").value("OPEN_NONCE_DUPLICATED"))
                .andExpect(jsonPath("$.message").value("请求已处理，请勿重放"));
        assertEquals(1L, nonceCount());
    }

    @Test
    void same_nonce_string_under_different_access_key_is_independent() throws Exception {
        // 不同调用方各自维护 nonce 空间（唯一键含 access_key）
        String nonce = freshNonce();
        mockMvc.perform(signedGet(BASE, nowMillis(), nonce))
                .andExpect(jsonPath("$.code").value("OK"));
        // 无第二把已配置密钥；改为直接落库验证唯一键维度
        jdbcTemplate.update("INSERT INTO t_open_api_nonce(access_key, nonce, expire_time, created_time) "
                + "VALUES ('other-ak', ?, ?, CURRENT_TIMESTAMP)", nonce,
                LocalDateTime.now().plusMinutes(30));
        assertEquals(2L, nonceCount());
    }

    // ---------------- 过期清理 ----------------

    @Test
    void purge_removes_only_expired_nonce() {
        LocalDateTime now = LocalDateTime.now();
        jdbcTemplate.update("INSERT INTO t_open_api_nonce(access_key, nonce, expire_time, created_time) "
                + "VALUES ('test-ak', 'n-expired-1', ?, CURRENT_TIMESTAMP)", now.minusMinutes(1));
        jdbcTemplate.update("INSERT INTO t_open_api_nonce(access_key, nonce, expire_time, created_time) "
                + "VALUES ('test-ak', 'n-expired-2', ?, CURRENT_TIMESTAMP)", now.minusMinutes(30));
        jdbcTemplate.update("INSERT INTO t_open_api_nonce(access_key, nonce, expire_time, created_time) "
                + "VALUES ('test-ak', 'n-fresh', ?, CURRENT_TIMESTAMP)", now.plusMinutes(20));

        int removed = nonceMaintenance.purgeExpired();
        assertEquals(2, removed);
        assertEquals(1L, nonceCount());
        Integer remaining = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM t_open_api_nonce WHERE nonce = 'n-fresh'", Integer.class);
        assertEquals(1, remaining);
    }

    // ---------------- 测试夹具：与生产同一套签名算法 ----------------

    private String freshNonce() {
        return "nonce-" + nonceSeq.incrementAndGet() + "-" + Thread.currentThread().getId();
    }

    private long nowMillis() {
        return System.currentTimeMillis();
    }

    private long nonceCount() {
        return jdbcTemplate.queryForObject("SELECT COUNT(*) FROM t_open_api_nonce", Long.class);
    }

    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder signedGet(
            String uri, long timestamp, String nonce) {
        SignedRequest req = sign(uri, timestamp, nonce);
        return get(req.uri)
                .header("X-Access-Key", ACCESS_KEY)
                .header("X-Timestamp", String.valueOf(req.timestamp))
                .header("X-Nonce", req.nonce)
                .header("X-Signature", req.signature);
    }

    private SignedRequest sign(String uri, long timestamp, String nonce) {
        return sign(uri, timestamp, nonce, ACCESS_KEY, SECRET);
    }

    private SignedRequest sign(String uri, long timestamp, String nonce, String accessKey, String secret) {
        String path = uri.contains("?") ? uri.substring(0, uri.indexOf('?')) : uri;
        String query = uri.contains("?") ? uri.substring(uri.indexOf('?') + 1) : "";
        List<String> entries = new ArrayList<>();
        if (!query.isEmpty()) {
            for (String pair : query.split("&")) {
                int eq = pair.indexOf('=');
                String key = eq < 0 ? pair : pair.substring(0, eq);
                String value = eq < 0 ? "" : urlDecode(pair.substring(eq + 1));
                entries.add(key + "=" + value);
            }
        }
        Collections.sort(entries);
        String canonical = "GET\n" + path + "\n" + String.join("&", entries) + "\n"
                + accessKey + "\n" + timestamp + "\n" + nonce;
        return new SignedRequest(uri, timestamp, nonce, hmacHex(secret, canonical));
    }

    private static String urlDecode(String value) {
        try {
            return java.net.URLDecoder.decode(value, "UTF-8");
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static String hmacHex(String secret, String content) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] digest = mac.doFinal(content.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                hex.append(Character.forDigit((b >> 4) & 0xF, 16));
                hex.append(Character.forDigit(b & 0xF, 16));
            }
            return hex.toString();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static class SignedRequest {
        final String uri;
        final long timestamp;
        final String nonce;
        final String signature;

        SignedRequest(String uri, long timestamp, String nonce, String signature) {
            this.uri = uri;
            this.timestamp = timestamp;
            this.nonce = nonce;
            this.signature = signature;
        }
    }
}
