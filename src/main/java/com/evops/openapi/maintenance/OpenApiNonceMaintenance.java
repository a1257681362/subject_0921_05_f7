package com.evops.openapi.maintenance;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.evops.common.trace.TraceContext;
import com.evops.openapi.config.OpenApiProperties;
import com.evops.openapi.entity.OpenApiNonce;
import com.evops.openapi.mapper.OpenApiNonceMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.time.LocalDateTime;
import java.util.List;

/**
 * nonce 表过期自动清理：
 * 1) 定时（默认每分钟）物理删除 expire_time 已过的行，分批防止单轮跑太久；
 * 2) 启动补扫一次：服务停机期间到期的行重启后立即清掉，不等下一个周期。
 * nonce 去重窗口为 30 分钟，清理周期远小于窗口，正常情况下表始终很小。
 * 本表是全库"禁止物理删除"约定的运维临时数据例外（同批量任务记录），仅存防重放凭据。
 */
@Component
public class OpenApiNonceMaintenance implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(OpenApiNonceMaintenance.class);

    @Resource
    private OpenApiNonceMapper nonceMapper;
    @Resource
    private OpenApiProperties properties;

    @Scheduled(cron = "${evops.openapi.nonce-cleanup-cron:23 * * * * ?}")
    public void scheduledSweep() {
        int removed = purgeExpired();
        if (removed > 0) {
            log.info("开放接口 nonce 过期清理：物理删除 {} 行", removed);
        }
    }

    /** 启动补扫：清掉停机期间到期的 nonce */
    @Override
    public void run(ApplicationArguments args) {
        TraceContext.ensureTrace();
        try {
            int removed = purgeExpired();
            if (removed > 0) {
                log.info("启动补扫：物理删除停机期间到期 nonce {} 行", removed);
            }
        } finally {
            TraceContext.clear();
        }
    }

    /**
     * 分批物理删除全部过期 nonce 行，返回删除行数。
     */
    public int purgeExpired() {
        int total = 0;
        List<OpenApiNonce> expired;
        int batchSize = properties.getCleanupBatchSize();
        do {
            expired = nonceMapper.selectList(new LambdaQueryWrapper<OpenApiNonce>()
                    .le(OpenApiNonce::getExpireTime, LocalDateTime.now())
                    .orderByAsc(OpenApiNonce::getId)
                    .last("LIMIT " + batchSize));
            if (!expired.isEmpty()) {
                List<Long> ids = expired.stream().map(OpenApiNonce::getId)
                        .collect(java.util.stream.Collectors.toList());
                int deleted = nonceMapper.deleteBatchIds(ids);
                total += deleted;
                // 理论上删除行数与查出数一致；不足一批说明已清完
                if (deleted < expired.size()) {
                    break;
                }
            }
        } while (expired.size() >= batchSize);
        return total;
    }
}
