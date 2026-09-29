package com.evops.openapi.nonce;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

/**
 * 对外开放接口签名请求的 nonce 留痕。运维临时数据（与 t_batch_job 同类，
 * 属全库"禁止物理删除"约定的例外）：expire_time 到期由定时任务物理清理。
 * 不继承 BaseEntity：无操作人/业务时间/版本号等业务审计列。
 */
@Getter
@Setter
@TableName("t_openapi_nonce")
public class OpenApiNonce {

    @TableId(type = IdType.AUTO)
    private Long id;

    /** 接入方 appId（与配置 evops.openapi.apps 的 key 对应） */
    private String appId;

    /** 一次性随机串 */
    private String nonce;

    /** 过期时间 = 入库时间 + nonce 保留窗口（默认 30 分钟），到期物理清理 */
    private LocalDateTime expireTime;

    private LocalDateTime createdTime;
}
