package com.evops.openapi.controller;

import com.evops.common.ApiResponse;
import com.evops.openapi.security.OpenApiSignInterceptor;
import com.evops.order.controller.OrderDetailAssembler;
import com.evops.order.entity.ProcessOrder;
import com.evops.order.service.ProcessOrderService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * 对外开放加工单查询（只读）。路径前缀 /open/api/**：
 * 不走 Shiro Basic，由 {@link OpenApiSignInterceptor} 做 HMAC 签名 + 时间窗 + nonce 防重放。
 * 仅暴露查询，不提供任何写操作；返回口径与内部接口一致（共用 OrderDetailAssembler）。
 */
@RestController
@RequestMapping("/open/api/orders")
public class OpenProcessOrderController {

    private final ProcessOrderService orderService;
    private final OrderDetailAssembler detailAssembler;

    public OpenProcessOrderController(ProcessOrderService orderService,
                                      OrderDetailAssembler detailAssembler) {
        this.orderService = orderService;
        this.detailAssembler = detailAssembler;
    }

    /** 按加工单号检索（主单 + 左右眼有效处方 + 状态流转记录 + 返修记录） */
    @GetMapping("/by-no/{orderNo}")
    public ApiResponse<Map<String, Object>> getByOrderNo(@PathVariable String orderNo) {
        ProcessOrder order = orderService.getByOrderNo(orderNo);
        return ApiResponse.ok(detailAssembler.assembleDetail(order));
    }

    @GetMapping("/{id}")
    public ApiResponse<Map<String, Object>> get(@PathVariable Long id) {
        ProcessOrder order = orderService.get(id);
        return ApiResponse.ok(detailAssembler.assembleDetail(order));
    }

    /** 列表检索（可按状态/门店过滤） */
    @GetMapping
    public ApiResponse<List<ProcessOrder>> list(@RequestParam(required = false) String status,
                                                @RequestParam(required = false) String storeCode) {
        return ApiResponse.ok(orderService.list(status, storeCode));
    }
}
