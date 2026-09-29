package com.evops.order.controller;

import com.evops.order.entity.ProcessOrder;
import com.evops.order.entity.ProcessOrderRx;
import com.evops.order.entity.ProcessOrderStatusLog;
import com.evops.order.entity.ProcessRework;
import com.evops.order.service.ProcessOrderService;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 加工单详情组装：主单 + 左右眼有效处方 + 状态流转记录 + 返修记录。
 * 内部接口（/api/orders）与对外开放查询（/open/api/orders）共用同一组装口径。
 */
@Component
public class OrderDetailAssembler {

    private final ProcessOrderService orderService;

    public OrderDetailAssembler(ProcessOrderService orderService) {
        this.orderService = orderService;
    }

    public Map<String, Object> assembleDetail(ProcessOrder order) {
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
