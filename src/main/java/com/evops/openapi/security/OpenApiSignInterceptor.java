package com.evops.openapi.security;

import com.evops.common.ApiResponse;
import com.evops.common.BizCode;
import com.evops.openapi.config.OpenApiProperties;
import com.evops.openapi.nonce.OpenApiNonceService;
import com.evops.openapi.sign.SignatureVerifier;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.annotation.Resource;
import java.time.Duration;
import java.time.Instant;
import java.util.regex.Pattern;

/**
 * 对外开放接口（/open/api/**）无状态签名鉴权。
 *
 * 校验顺序：
 *   1) 四个头齐全、时间戳可解析为毫秒、nonce 格式合法、appId 已登记 —— 任一不满足 SIGN_INVALID；
 *   2) |now - timestamp| &gt; 15 分钟 —— SIGN_EXPIRED；
 *   3) 用该 app 的 secret 重算 HMAC-SHA256 并常量时间比对 —— 不符 SIGN_INVALID；
 *   4) 占用 nonce（先验签后落库，未授权方无法灌表）—— 重复 NONCE_DUPLICATED。
 *
 * 安全要求：所有失败只回固定专用码与固定文案，不告知缺哪个头/差在哪里；
 * 细节（含 appId、失败原因）仅写服务端 warn 日志，借 traceId 关联现场。
 */
@Component
public class OpenApiSignInterceptor implements HandlerInterceptor {

    public static final String HEADER_APP = "X-Access-App";
    public static final String HEADER_TIMESTAMP = "X-Timestamp";
    public static final String HEADER_NONCE = "X-Nonce";
    public static final String HEADER_SIGNATURE = "X-Signature";

    /** nonce：8~64 位字母数字下划线连字符（与表列 VARCHAR(64) 对齐，防超长灌库） */
    private static final Pattern NONCE_PATTERN = Pattern.compile("[A-Za-z0-9_-]{8,64}");

    private static final Logger log = LoggerFactory.getLogger(OpenApiSignInterceptor.class);

    @Resource
    private OpenApiProperties properties;
    @Resource
    private SignatureVerifier verifier;
    @Resource
    private OpenApiNonceService nonceService;
    @Resource
    private ObjectMapper objectMapper;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        String appId = request.getHeader(HEADER_APP);
        String timestamp = request.getHeader(HEADER_TIMESTAMP);
        String nonce = request.getHeader(HEADER_NONCE);
        String signature = request.getHeader(HEADER_SIGNATURE);

        String secret = properties.secretOf(appId);
        long ts;
        if (secret == null
                || timestamp == null || timestamp.isEmpty()
                || nonce == null || !NONCE_PATTERN.matcher(nonce).matches()
                || signature == null || signature.isEmpty()
                || (ts = parseEpochMillis(timestamp)) < 0) {
            // 头缺失/格式非法/未知 app：统一一个码，不区分具体原因
            log.warn("对外接口签名前置校验未通过 uri={}", request.getRequestURI());
            reject(response, BizCode.SIGN_INVALID);
            return false;
        }

        // 时间窗：过早（重放历史请求）与过远的未来（时钟错乱/预签名囤积）都拒收
        long offsetMs = Math.abs(Instant.now().toEpochMilli() - ts);
        if (offsetMs > Duration.ofMinutes(properties.getTimestampWindowMinutes()).toMillis()) {
            log.warn("对外接口请求超出时间窗 appId={} offsetMs={}", appId, offsetMs);
            reject(response, BizCode.SIGN_EXPIRED);
            return false;
        }

        String canonicalQuery = verifier.canonicalQuery(request);
        String stringToSign = verifier.buildStringToSign(
                request.getMethod(), request.getRequestURI(), timestamp, nonce, canonicalQuery);
        String expected = verifier.hmacSha256Hex(stringToSign, secret);
        if (!verifier.matches(expected, signature.trim())) {
            log.warn("对外接口验签未通过 appId={} uri={}", appId, request.getRequestURI());
            reject(response, BizCode.SIGN_INVALID);
            return false;
        }

        // 验签通过才占用 nonce：唯一约束冲突即重放，直接拒绝
        if (!nonceService.tryConsume(appId, nonce)) {
            reject(response, BizCode.NONCE_DUPLICATED);
            return false;
        }
        return true;
    }

    /** 毫秒时间戳解析；非数字/溢出等统一视为非法 */
    private static long parseEpochMillis(String text) {
        try {
            long value = Long.parseLong(text.trim());
            return value < 0 ? -1L : value;
        } catch (NumberFormatException ex) {
            return -1L;
        }
    }

    /** 失败出口：HTTP 401 + 固定业务码，响应体不含任何失败细节 */
    private void reject(HttpServletResponse response, BizCode bizCode) throws Exception {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(objectMapper.writeValueAsString(ApiResponse.fail(bizCode)));
    }
}
