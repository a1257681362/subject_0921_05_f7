package com.evops.openapi;

import com.evops.openapi.nonce.OpenApiNonceService;
import com.evops.openapi.sign.SignatureVerifier;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.shiro.spring.web.config.DefaultShiroFilterChainDefinition;
import org.apache.shiro.spring.web.config.ShiroFilterChainDefinition;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import javax.annotation.Resource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 对外开放加工单查询 HMAC 鉴权集成测试：
 * 正常签名 / 参数乱序 / 坏签名与篡改 / 时间窗 / nonce 重放 / 过期清理 / 失败响应不泄露细节。
 */
@SpringBootTest(properties = "evops.openapi.apps.test-app=test-secret")
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(OpenApiSignIntegrationTest.TestShiroBypass.class)
class OpenApiSignIntegrationTest {

    private static final String APP_ID = "test-app";
    private static final String APP_SECRET = "test-secret";

    @TestConfiguration
    static class TestShiroBypass {
        @Bean
        ShiroFilterChainDefinition shiroFilterChainDefinition() {
            DefaultShiroFilterChainDefinition chain = new DefaultShiroFilterChainDefinition();
            chain.addPathDefinition("/**", "anon");
            return chain;
        }
    }

    @Resource
    private MockMvc mockMvc;
    @Resource
    private ObjectMapper objectMapper;
    @Resource
    private JdbcTemplate jdbcTemplate;
    @Autowired
    private SignatureVerifier verifier;
    @Autowired
    private OpenApiNonceService nonceService;

    private long operatorSeq = 2000;

    /** 静态计数：同一测试类共享 Spring 上下文，nonce 必须跨用例唯一 */
    private static final java.util.concurrent.atomic.AtomicInteger NONCE_SEQ =
            new java.util.concurrent.atomic.AtomicInteger();

    // ---------------- 正常路径 ----------------

    @Test
    void signed_query_by_order_no_succeeds() throws Exception {
        long lensId = createLens("L-OPEN-1");
        createOrder("O-OPEN-1", lensId);

        mockMvc.perform(signedGet("/open/api/orders/by-no/O-OPEN-1", ""))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value("OK"))
                .andExpect(jsonPath("$.data.order.orderNo").value("O-OPEN-1"))
                .andExpect(jsonPath("$.data.prescriptions.length()").value(2));
    }

    @Test
    void signed_list_succeeds_and_param_send_order_does_not_matter() throws Exception {
        long lensId = createLens("L-OPEN-2");
        createOrder("O-OPEN-2", lensId);

        String canonical = "status=CREATED&storeCode=S01"; // 字典序 canonical
        // 参数以 canonical 顺序发送
        mockMvc.perform(signedGet("/open/api/orders", canonical, canonical))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value("OK"))
                .andExpect(jsonPath("$.data[0].storeCode").value("S01"));

        // 签名仍按 canonical 计算，参数乱序发送：服务端重排后必须验过
        mockMvc.perform(signedGet("/open/api/orders", "storeCode=S01&status=CREATED", canonical))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value("OK"));
    }

    // ---------------- 验签失败：统一专用码 ----------------

    @Test
    void wrong_signature_rejected_without_detail() throws Exception {
        // 四头齐全但签名是随便填的（不能用 .header 覆盖：MockMvc 同名头为追加，getHeader 取首个）
        long ts = System.currentTimeMillis();
        String nonce = freshNonce();
        mockMvc.perform(get("/open/api/orders/by-no/O-OPEN-X")
                        .header("X-Access-App", APP_ID)
                        .header("X-Timestamp", String.valueOf(ts))
                        .header("X-Nonce", nonce)
                        .header("X-Signature", "deadbeef"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.code").value("SIGN_INVALID"))
                // 文案固定，不含 uri/缺哪个头/期望值等任何细节
                .andExpect(jsonPath("$.message").value("请求签名校验未通过"));
    }

    @Test
    void tampered_query_value_rejected() throws Exception {
        // 按 status=READY 签名，实际发送偷换成 CREATED：服务端 canonical 与签名串不一致
        long ts = System.currentTimeMillis();
        String nonce = freshNonce();
        String sig = sign("/open/api/orders", "status=READY&storeCode=S01", ts, nonce);
        mockMvc.perform(get("/open/api/orders")
                        .header("X-Access-App", APP_ID)
                        .header("X-Timestamp", String.valueOf(ts))
                        .header("X-Nonce", nonce)
                        .header("X-Signature", sig)
                        .param("status", "CREATED")
                        .param("storeCode", "S01"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("SIGN_INVALID"));
    }

    @Test
    void unknown_app_and_missing_header_rejected() throws Exception {
        // 未知 appId：签名就算按 test-secret 正确也算 SIGN_INVALID
        long ts = System.currentTimeMillis();
        String nonce = freshNonce();
        String sig = sign("/open/api/orders", "", ts, nonce);
        mockMvc.perform(get("/open/api/orders")
                        .header("X-Access-App", "not-registered")
                        .header("X-Timestamp", String.valueOf(ts))
                        .header("X-Nonce", nonce)
                        .header("X-Signature", sig))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("SIGN_INVALID"));

        // 缺 nonce 头：同一个码，不区分具体缺失项
        mockMvc.perform(get("/open/api/orders")
                        .header("X-Access-App", APP_ID)
                        .header("X-Timestamp", String.valueOf(System.currentTimeMillis()))
                        .header("X-Signature", "whatever"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("SIGN_INVALID"));
    }

    @Test
    void malformed_nonce_rejected() throws Exception {
        long ts = System.currentTimeMillis();
        String nonce = "bad nonce!"; // 含空格和感叹号，不符合 [A-Za-z0-9_-]{8,64}
        String sig = sign("/open/api/orders", "", ts, nonce);
        mockMvc.perform(get("/open/api/orders")
                        .header("X-Access-App", APP_ID)
                        .header("X-Timestamp", String.valueOf(ts))
                        .header("X-Nonce", nonce)
                        .header("X-Signature", sig))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("SIGN_INVALID"));
    }

    // ---------------- 时间窗 ----------------

    @Test
    void timestamp_outside_window_rejected_inside_accepted() throws Exception {
        long now = System.currentTimeMillis();
        long sixteenMin = 16L * 60 * 1000;
        long fourteenMin = 14L * 60 * 1000;

        mockMvc.perform(signedGet("/open/api/orders/by-no/O-OPEN-1", "", "", now - sixteenMin, freshNonce()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("SIGN_EXPIRED"))
                .andExpect(jsonPath("$.message").value("请求已超出允许的时间窗口"));

        mockMvc.perform(signedGet("/open/api/orders/by-no/O-OPEN-1", "", "", now + sixteenMin, freshNonce()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("SIGN_EXPIRED"));

        // 边界内（14 分钟）即使单据不存在也应通过鉴权（后续走 ORDER_NOT_FOUND）
        mockMvc.perform(signedGet("/open/api/orders/by-no/NO-SUCH-ORDER", "", "", now - fourteenMin, freshNonce()))
                .andExpect(jsonPath("$.code").value("ORDER_NOT_FOUND"));
    }

    // ---------------- nonce 防重放 ----------------

    @Test
    void duplicated_nonce_rejected_and_only_one_row_kept() throws Exception {
        long lensId = createLens("L-OPEN-3");
        createOrder("O-OPEN-3", lensId);

        long ts = System.currentTimeMillis();
        String nonce = freshNonce();
        MockHttpServletRequestBuilder first = signedGet("/open/api/orders/by-no/O-OPEN-3", "", "", ts, nonce);
        mockMvc.perform(first).andExpect(status().isOk()).andExpect(jsonPath("$.code").value("OK"));

        // 完全相同的请求（同 nonce）重放：直接拒绝
        mockMvc.perform(signedGet("/open/api/orders/by-no/O-OPEN-3", "", "", ts, nonce))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("NONCE_DUPLICATED"))
                .andExpect(jsonPath("$.message").value("请求不可重复提交"));

        Integer rows = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM t_openapi_nonce WHERE app_id=? AND nonce=?",
                Integer.class, APP_ID, nonce);
        assertEquals(1, rows, "重放不得产生第二行");
    }

    // ---------------- 过期清理 ----------------

    @Test
    void purge_removes_only_expired_nonce_rows() throws Exception {
        long ts = System.currentTimeMillis();
        jdbcTemplate.update(
                "INSERT INTO t_openapi_nonce(app_id, nonce, expire_time, created_time) VALUES (?,?,DATEADD('MINUTE',-1,CURRENT_TIMESTAMP),CURRENT_TIMESTAMP)",
                APP_ID, "expired-nonce-001");
        String freshNonce = freshNonce();
        String sig = sign("/open/api/orders", "", ts, freshNonce);
        mockMvc.perform(get("/open/api/orders")
                        .header("X-Access-App", APP_ID)
                        .header("X-Timestamp", String.valueOf(ts))
                        .header("X-Nonce", freshNonce)
                        .header("X-Signature", sig))
                .andExpect(status().isOk());

        int removed = nonceService.purgeExpired();
        assertEquals(1, removed);

        Integer expiredLeft = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM t_openapi_nonce WHERE nonce='expired-nonce-001'", Integer.class);
        Integer freshLeft = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM t_openapi_nonce WHERE app_id=? AND nonce=?",
                Integer.class, APP_ID, freshNonce);
        assertEquals(0, expiredLeft, "到期行必须物理删除");
        assertEquals(1, freshLeft, "未到期行必须保留");
    }

    // ---------------- 辅助方法 ----------------

    private MockHttpServletRequestBuilder signedGet(String uri, String sentQuery) {
        // 默认发送串已是 canonical；乱序场景用三参版本显式给出 canonical
        return signedGet(uri, sentQuery, sentQuery, System.currentTimeMillis(), freshNonce());
    }

    private MockHttpServletRequestBuilder signedGet(String uri, String sentQuery, String canonicalQuery) {
        return signedGet(uri, sentQuery, canonicalQuery, System.currentTimeMillis(), freshNonce());
    }

    private MockHttpServletRequestBuilder signedGet(String uri, String sentQuery, String canonicalQuery,
                                                    long timestamp, String nonce) {
        String sig = sign(uri, canonicalQuery, timestamp, nonce);
        return get(uri + (sentQuery.isEmpty() ? "" : "?" + sentQuery))
                .header("X-Access-App", APP_ID)
                .header("X-Timestamp", String.valueOf(timestamp))
                .header("X-Nonce", nonce)
                .header("X-Signature", sig);
    }

    private String sign(String uri, String canonicalQuery, long timestamp, String nonce) {
        String stringToSign = verifier.buildStringToSign(
                "GET", uri, String.valueOf(timestamp), nonce, canonicalQuery);
        return verifier.hmacSha256Hex(stringToSign, APP_SECRET);
    }

    private String freshNonce() {
        return String.format("nonce-%08d", NONCE_SEQ.incrementAndGet());
    }

    private long createLens(String code) throws Exception {
        String body = "{\"lensCode\":\"" + code + "\",\"lensName\":\"镜片\",\"lensType\":\"单光\",\"price\":399.00}";
        String resp = mockMvc.perform(post("/api/lens").contentType(MediaType.APPLICATION_JSON)
                        .header("X-Operator-Id", String.valueOf(++operatorSeq))
                        .header("X-Request-No", code + "-lens")
                        .content(body))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        JsonNode node = objectMapper.readTree(resp);
        return node.get("data").get("id").asLong();
    }

    private void createOrder(String orderNo, long lensId) throws Exception {
        String body = "{\"orderNo\":\"" + orderNo + "\",\"lensId\":" + lensId
                + ",\"customerName\":\"张三\",\"storeCode\":\"S01\","
                + "\"prescriptions\":["
                + "{\"eye\":\"L\",\"sphere\":-1.00},"
                + "{\"eye\":\"R\",\"sphere\":-1.00}]}";
        mockMvc.perform(post("/api/orders").contentType(MediaType.APPLICATION_JSON)
                        .header("X-Operator-Id", String.valueOf(++operatorSeq))
                        .header("X-Request-No", orderNo + "-create")
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value("OK"));
    }
}
