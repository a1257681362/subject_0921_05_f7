package com.evops.config;

import org.apache.shiro.realm.Realm;
import org.apache.shiro.realm.SimpleAccountRealm;
import org.apache.shiro.spring.web.config.DefaultShiroFilterChainDefinition;
import org.apache.shiro.spring.web.config.ShiroFilterChainDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ShiroConfig {
    @Bean
    public Realm localRealm() {
        SimpleAccountRealm realm = new SimpleAccountRealm();
        realm.addAccount("bootstrap", "bootstrap", "system");
        return realm;
    }

    @Bean
    public ShiroFilterChainDefinition shiroFilterChainDefinition() {
        DefaultShiroFilterChainDefinition chain = new DefaultShiroFilterChainDefinition();
        chain.addPathDefinition("/api/health", "anon");
        chain.addPathDefinition("/error", "anon");
        // 对外开放接口不走内部账号：Shiro 放行，由 HMAC 签名拦截器鉴权（须排在 /api/** 之前）
        chain.addPathDefinition("/open/api/**", "anon");
        // 纯接口走 HTTP Basic（未认证返回 401 而非表单登录页 302）；其余路径保持表单认证
        chain.addPathDefinition("/api/**", "authcBasic");
        chain.addPathDefinition("/**", "authc");
        return chain;
    }
}
