package com.evops.openapi.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 对外开放接口安全配置（前缀 evops.openapi）：
 * access-keys 为调用方 accessKey -> HMAC 密钥映射，生产环境通过外部配置/环境变量注入，
 * 不要把真实密钥提交进仓库；其余为时间窗与 nonce 去重窗口（与需求约定：15 分钟 / 30 分钟）。
 */
@Component
@ConfigurationProperties(prefix = "evops.openapi")
public class OpenApiProperties {

    /** 调用方凭据：accessKey -> secret（HMAC-SHA256 密钥） */
    private Map<String, String> accessKeys = new LinkedHashMap<>();

    /** 时间戳允许偏差（秒），超过即拒收，默认 15 分钟 */
    private long timestampWindowSeconds = 900;

    /** nonce 去重保留窗口（分钟），默认 30 分钟；到期行由定时任务物理清理 */
    private int nonceTtlMinutes = 30;

    /** nonce 过期清理执行时刻（默认每分钟第 23 秒，避开整分）；启动时另补扫一次 */
    private String nonceCleanupCron = "23 * * * * ?";

    /** 单批清理上限，防止积压时单轮跑太久 */
    private int cleanupBatchSize = 500;

    public Map<String, String> getAccessKeys() { return accessKeys; }
    public void setAccessKeys(Map<String, String> accessKeys) { this.accessKeys = accessKeys; }

    public long getTimestampWindowSeconds() { return timestampWindowSeconds; }
    public void setTimestampWindowSeconds(long timestampWindowSeconds) {
        this.timestampWindowSeconds = timestampWindowSeconds;
    }

    public int getNonceTtlMinutes() { return nonceTtlMinutes; }
    public void setNonceTtlMinutes(int nonceTtlMinutes) { this.nonceTtlMinutes = nonceTtlMinutes; }

    public String getNonceCleanupCron() { return nonceCleanupCron; }
    public void setNonceCleanupCron(String nonceCleanupCron) {
        this.nonceCleanupCron = nonceCleanupCron;
    }

    public int getCleanupBatchSize() { return cleanupBatchSize; }
    public void setCleanupBatchSize(int cleanupBatchSize) { this.cleanupBatchSize = cleanupBatchSize; }
}
