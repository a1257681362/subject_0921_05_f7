package com.evops.openapi.nonce;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.evops.openapi.config.OpenApiProperties;
import com.evops.openapi.mapper.OpenApiNonceMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.time.LocalDateTime;

/**
 * nonce 消费与过期清理。
 * (app_id, nonce) 唯一约束是重复的权威判定（并发安全）：插入冲突即重放，直接拒绝。
 */
@Service
public class OpenApiNonceService {

    private static final Logger log = LoggerFactory.getLogger(OpenApiNonceService.class);

    @Resource
    private OpenApiNonceMapper nonceMapper;
    @Resource
    private OpenApiProperties properties;

    /**
     * 尝试占用一个 nonce。
     * @return true 首次使用（已落库，30 分钟后可清理）；false 该 appId 下 nonce 已存在（重放）
     */
    public boolean tryConsume(String appId, String nonce) {
        OpenApiNonce record = new OpenApiNonce();
        record.setAppId(appId);
        record.setNonce(nonce);
        LocalDateTime now = LocalDateTime.now();
        record.setCreatedTime(now);
        record.setExpireTime(now.plusMinutes(properties.getNonceRetainMinutes()));
        try {
            nonceMapper.insert(record);
            return true;
        } catch (DuplicateKeyException ex) {
            // uk_openapi_nonce 冲突：重放。库层判定，避免"先查后插"的并发窗口
            log.warn("对外接口 nonce 重放已拒绝 appId={}", appId);
            return false;
        }
    }

    /**
     * 物理删除 expire_time 已过的 nonce 行，返回删除条数。
     */
    public int purgeExpired() {
        return nonceMapper.delete(new LambdaQueryWrapper<OpenApiNonce>()
                .le(OpenApiNonce::getExpireTime, LocalDateTime.now()));
    }
}
