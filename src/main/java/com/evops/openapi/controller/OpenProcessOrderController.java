package com.evops.openapi.controller;

import com.evops.common.ApiResponse;
import com.evops.order.entity.ProcessOrder;
import com.evops.order.entity.ProcessOrderRx;
import com.evops.order.entity.ProcessOrderStatusLog;
import com.evops.order.entity.ProcessRework;
import com.evops.order.service.ProcessOrderService;
import com.evops.openapi.security.OpenApiSignatureInterceptor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 对外开放加工单查询（只读）。不走内部账号体系，统一由
 * {@link OpenApiSignatureInterceptor} 做 HMAC 验签 + 时间窗 + nonce 防重放；
 * Shiro 对 /open/api/** 放行（anon），鉴权完全以签名为准。
 */
@RestController
@RequestMapping("/open/api/orders")
public class OpenProcessOrderController {

    private final ProcessOrderService orderService;

    public OpenProcessOrderController(ProcessOrderService orderService) {
        this.orderService = orderService;
    }

    /** 按加工单号检索（主单 + 左右眼有效处方 + 状态流转记录 + 返修记录），结构与内部接口一致 */
    @GetMapping("/by-no/{orderNo}")
    public ApiResponse<Map<String, Object>> getByOrderNo(@PathVariable String orderNo) {
        ProcessOrder order = orderService.getByOrderNo(orderNo);
        return ApiResponse.ok(assembleDetail(order));
    }

    /** 按状态/门店列单（只读，仅返回主单字段） */
    @GetMapping
    public ApiResponse<List<ProcessOrder>> list(@RequestParam(required = false) String status,
                                                @RequestParam(required = false) String storeCode) {
        return ApiResponse.ok(orderService.list(status, storeCode));
    }

    private Map<String, Object> assembleDetail(ProcessOrder order) {
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("order", order);
        List<ProcessOrderRx> prescriptions = orderService.listActivePrescriptions(order.getId());
        detail.put("prescriptions", prescriptions);
        List<ProcessOrderStatusLog> statusLogs = orderService.listStatusLogs(order.getId());
        detail.put("statusLogs", statusLogs);
        List<ProcessRework> reworks = orderService.listReworks(order.getId());
        detail.put("reworks", reworks);
        return detail;
    }
}
