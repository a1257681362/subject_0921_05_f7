package com.evops.config;

import com.evops.openapi.security.OpenApiSignatureInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.annotation.Resource;

@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    @Resource
    private RequestContextInterceptor requestContextInterceptor;
    @Resource
    private OpenApiSignatureInterceptor openApiSignatureInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(requestContextInterceptor).addPathPatterns("/api/**");
        // 对外开放接口单独一条链：不走内部审计头，鉴权以 HMAC 签名为准
        registry.addInterceptor(openApiSignatureInterceptor).addPathPatterns("/open/api/**");
    }
}
