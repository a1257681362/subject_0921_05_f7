package com.evops.openapi.security;

import com.evops.common.BizCode;
import com.evops.common.BizException;
import com.evops.openapi.config.OpenApiProperties;
import com.evops.openapi.entity.OpenApiNonce;
import com.evops.openapi.mapper.OpenApiNonceMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * 开放接口 HMAC 验签与防重放。
 *
 * 待签名串（6 行，\n 分隔）：
 *   HTTP 方法（大写）
 *   请求路径（含 contextPath，不含 query）
 *   业务参数：query 全部参数按 "key=value" 字典序排列后 & 连接（多值参数每个值一项；值为表单解码后的原文）
 *   accessKey
 *   timestamp（epoch 毫秒）
 *   nonce
 * 以 accessKey 对应密钥做 HMAC-SHA256，小写十六进制。
 *
 * 拒绝策略：时间戳偏差超过 15 分钟拒收；验签通过后 nonce 落库，(access_key, nonce)
 * 唯一约束兜底，重复直接拒绝。任何验签类失败对外只抛 OPEN_SIGN_INVALID，
 * 具体原因只写服务端日志，不向调用方透露。
 */
@Service
public class OpenApiSignatureVerifier {

    private static final Logger log = LoggerFactory.getLogger(OpenApiSignatureVerifier.class);

    public static final String HEADER_ACCESS_KEY = "X-Access-Key";
    public static final String HEADER_TIMESTAMP = "X-Timestamp";
    public static final String HEADER_NONCE = "X-Nonce";
    public static final String HEADER_SIGNATURE = "X-Signature";

    private static final String HMAC_SHA256 = "HmacSHA256";
    private static final int NONCE_MAX_LENGTH = 64;

    @Resource
    private OpenApiProperties properties;
    @Resource
    private OpenApiNonceMapper nonceMapper;

    /**
     * 校验并消费本次请求的防重放凭据；不通过抛 BizException（统一出口转专用响应码）。
     */
    public void verify(HttpServletRequest request) {
        String accessKey = trimToNull(request.getHeader(HEADER_ACCESS_KEY));
        String timestampText = trimToNull(request.getHeader(HEADER_TIMESTAMP));
        String nonce = trimToNull(request.getHeader(HEADER_NONCE));
        String signature = trimToNull(request.getHeader(HEADER_SIGNATURE));

        // 缺头不区分缺哪一个：对外一律"签名校验未通过"
        if (accessKey == null || timestampText == null || nonce == null || signature == null) {
            throw reject(request, accessKey, "missing_header");
        }
        if (nonce.length() > NONCE_MAX_LENGTH) {
            throw reject(request, accessKey, "nonce_too_long");
        }

        String secret = properties.getAccessKeys().get(accessKey);
        if (secret == null) {
            throw reject(request, accessKey, "unknown_access_key");
        }

        long timestampMillis;
        try {
            timestampMillis = Long.parseLong(timestampText);
        } catch (NumberFormatException ex) {
            throw reject(request, accessKey, "bad_timestamp");
        }
        long driftSeconds = Duration.between(Instant.ofEpochMilli(timestampMillis), Instant.now()).abs().getSeconds();
        if (driftSeconds > properties.getTimestampWindowSeconds()) {
            throw reject(request, accessKey, "timestamp_out_of_window");
        }

        String canonical = buildCanonicalString(request, accessKey, timestampText, nonce);
        if (!constantTimeEquals(hmacHex(secret, canonical), signature)) {
            throw reject(request, accessKey, "signature_mismatch");
        }

        // 验签通过才消费 nonce：唯一约束兜底并发重放
        OpenApiNonce row = new OpenApiNonce();
        row.setAccessKey(accessKey);
        row.setNonce(nonce);
        row.setExpireTime(LocalDateTime.now().plusMinutes(properties.getNonceTtlMinutes()));
        try {
            nonceMapper.insert(row);
        } catch (DuplicateKeyException ex) {
            log.warn("开放接口 nonce 重放拒绝 path={} accessKey={}", request.getRequestURI(), accessKey);
            throw new BizException(BizCode.OPEN_NONCE_DUPLICATED);
        }
    }

    /**
     * 构造待签名串。包级可见便于单测与文档对齐。
     */
    String buildCanonicalString(HttpServletRequest request, String accessKey,
                                String timestampText, String nonce) {
        String method = request.getMethod().toUpperCase();
        String path = request.getRequestURI();
        return method + "\n"
                + path + "\n"
                + canonicalQuery(request) + "\n"
                + accessKey + "\n"
                + timestampText + "\n"
                + nonce;
    }

    /**
     * 参数按字典序排序：多值参数每个值展开成一项 "key=value"，整体排序后 & 连接，
     * 保证调用方参数顺序任意、验签结果一致。值取表单解码后的原文（无值参数 value 为空串）。
     * 用可重复列表而非 Set：同名同值的多值参数也要逐项保留。
     */
    private String canonicalQuery(HttpServletRequest request) {
        List<String> entries = new ArrayList<>();
        for (Map.Entry<String, String[]> entry : request.getParameterMap().entrySet()) {
            String[] values = entry.getValue();
            if (values == null || values.length == 0) {
                entries.add(entry.getKey() + "=");
                continue;
            }
            for (String value : values) {
                entries.add(entry.getKey() + "=" + (value == null ? "" : value));
            }
        }
        Collections.sort(entries);
        return String.join("&", entries);
    }

    private String hmacHex(String secret, String content) {
        try {
            Mac mac = Mac.getInstance(HMAC_SHA256);
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), HMAC_SHA256));
            byte[] digest = mac.doFinal(content.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                hex.append(Character.forDigit((b >> 4) & 0xF, 16));
                hex.append(Character.forDigit(b & 0xF, 16));
            }
            return hex.toString();
        } catch (Exception ex) {
            // 算法/JDK 固定存在，初始化失败属环境异常
            throw new IllegalStateException("HMAC-SHA256 不可用", ex);
        }
    }

    /** 定长比较，避免时序侧信道 */
    private boolean constantTimeEquals(String expected, String actual) {
        byte[] a = expected.getBytes(StandardCharsets.UTF_8);
        byte[] b = actual.getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(a, b);
    }

    private BizException reject(HttpServletRequest request, String accessKey, String reason) {
        log.warn("开放接口验签拒绝 path={} accessKey={} reason={}",
                request.getRequestURI(), accessKey, reason);
        return new BizException(BizCode.OPEN_SIGN_INVALID);
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
