package com.evops.openapi.security;

import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 对外开放接口（/open/api/**）统一验签入口：参数排序 HMAC 签名、15 分钟时间窗、
 * nonce 去重均在 {@link OpenApiSignatureVerifier} 内完成；不通过抛 BizException，
 * 由全局异常出口转专用码，细节不回传调用方。
 */
@Component
public class OpenApiSignatureInterceptor implements HandlerInterceptor {

    @Resource
    private OpenApiSignatureVerifier verifier;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        verifier.verify(request);
        return true;
    }
}
