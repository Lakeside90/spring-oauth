package com.demozi.res.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;

/**
 * @author Created by jianwu6 on 2019/10/14 16:28
 */
@Configuration
@EnableResourceServer
public class OAuth2ResourceServer extends ResourceServerConfigurerAdapter {



    @Bean
    public RemoteTokenServices tokenServices() {
        //token验证信息，  令牌+客户端账号 发送到授权服务端 完成验证
        RemoteTokenServices tokenService = new RemoteTokenServices();
        tokenService.setCheckTokenEndpointUrl("http://localhost:8081/oauth/check_token");
        tokenService.setClientId("clientId");
        tokenService.setClientSecret("secret");
        return tokenService;
    }


    @Override
    public void configure(HttpSecurity http) throws Exception {

        /**
         * 只拦截 /api/ 下的接口
         */
        http.authorizeRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/api/**").authenticated();
    }
}
