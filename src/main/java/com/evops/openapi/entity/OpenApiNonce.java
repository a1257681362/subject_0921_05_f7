package com.evops.openapi.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

/**
 * 开放接口一次性随机数留痕（防重放）。
 * 仅存调用方标识、nonce 与过期时刻：验签通过后落库，(access_key, nonce) 唯一约束
 * 兜底并发重放；expire_time 到期（30 分钟）由定时任务物理清理。
 * 属运维临时数据，不带业务审计字段，不继承 BaseEntity。
 */
@Getter
@Setter
@TableName("t_open_api_nonce")
public class OpenApiNonce {

    @TableId(type = IdType.AUTO)
    private Long id;

    private String accessKey;
    private String nonce;
    /** 去重保留至（落库时间 + 30 分钟），到期物理清理 */
    private LocalDateTime expireTime;
    private LocalDateTime createdTime;
}
