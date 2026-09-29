package com.evops.openapi.maintenance;

import com.evops.common.trace.TraceContext;
import com.evops.openapi.config.OpenApiProperties;
import com.evops.openapi.nonce.OpenApiNonceService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;

/**
 * 过期 nonce 自动清理（写法对齐 QuotaMaintenance）：
 * 1) 定时（默认每分钟第 43 秒）物理删除 expire_time 已过的 nonce 行；
 * 2) 启动补扫一次：清理停机期间已到期、未来得及删的行。
 * 保留窗口 30 分钟 &gt; 签名时间窗 15 分钟，清理不会误删时间窗内仍可能重放的 nonce。
 */
@Component
public class OpenApiNonceMaintenance implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(OpenApiNonceMaintenance.class);

    @Resource
    private OpenApiNonceService nonceService;
    @Resource
    private OpenApiProperties properties;

    @Scheduled(cron = "${evops.openapi.cleanup-cron:43 * * * * ?}")
    public void scheduledPurge() {
        int removed = nonceService.purgeExpired();
        if (removed > 0) {
            log.info("对外接口 nonce 过期清理：物理删除 {} 行", removed);
        }
    }

    @Override
    public void run(ApplicationArguments args) {
        TraceContext.ensureTrace();
        try {
            int removed = nonceService.purgeExpired();
            if (removed > 0) {
                log.info("启动补扫：物理删除停机期间到期 nonce {} 行", removed);
            }
        } finally {
            TraceContext.clear();
        }
    }

    /** cron 仅用于读取确认配置已绑定（清理节奏可运维调整） */
    public String currentCron() {
        return properties.getCleanupCron();
    }
}
