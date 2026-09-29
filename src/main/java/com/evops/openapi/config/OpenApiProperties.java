package com.evops.openapi.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.Map;

/**
 * 对外开放接口配置（evops.openapi.*）：
 * apps 为接入方 appId -> secret（密钥走环境变量/外部配置，不入库不入代码）；
 * 签名时间窗、nonce 保留窗口、过期清理 cron。
 *
 * 约束：nonce 保留窗口必须大于签名时间窗——清理任务才不会在时间窗内提前删掉未过期 nonce。
 */
@Component
@ConfigurationProperties(prefix = "evops.openapi")
public class OpenApiProperties {

    /** appId -> secret；未配置任何 app 时所有对外请求一律拒绝 */
    private Map<String, String> apps = Collections.emptyMap();

    /** 请求时间戳允许的时钟偏移（分钟），超出 [now-w, now+w] 拒收 */
    private int timestampWindowMinutes = 15;

    /** nonce 去重保留窗口（分钟），到期行定时物理清理；必须大于 timestampWindowMinutes */
    private int nonceRetainMinutes = 30;

    /** 过期 nonce 清理 cron（默认每分钟第 43 秒，避开整点） */
    private String cleanupCron = "43 * * * * ?";

    public Map<String, String> getApps() { return apps; }
    public void setApps(Map<String, String> apps) { this.apps = apps; }

    public int getTimestampWindowMinutes() { return timestampWindowMinutes; }
    public void setTimestampWindowMinutes(int timestampWindowMinutes) {
        this.timestampWindowMinutes = timestampWindowMinutes;
    }

    public int getNonceRetainMinutes() { return nonceRetainMinutes; }
    public void setNonceRetainMinutes(int nonceRetainMinutes) {
        this.nonceRetainMinutes = nonceRetainMinutes;
    }

    public String getCleanupCron() { return cleanupCron; }
    public void setCleanupCron(String cleanupCron) { this.cleanupCron = cleanupCron; }

    /** 未配置 secret 的 appId 视同未知 app，避免空串密钥参与签名 */
    public String secretOf(String appId) {
        if (appId == null || apps == null) {
            return null;
        }
        String secret = apps.get(appId);
        return secret == null || secret.isEmpty() ? null : secret;
    }
}
