package com.evops.config;

import com.evops.openapi.security.OpenApiSignInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.annotation.Resource;

@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    @Resource
    private RequestContextInterceptor requestContextInterceptor;
    @Resource
    private OpenApiSignInterceptor openApiSignInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(requestContextInterceptor).addPathPatterns("/api/**");
        // 对外开放查询：HMAC 签名 / 15 分钟时间窗 / nonce 30 分钟防重放
        registry.addInterceptor(openApiSignInterceptor).addPathPatterns("/open/api/**");
    }
}
