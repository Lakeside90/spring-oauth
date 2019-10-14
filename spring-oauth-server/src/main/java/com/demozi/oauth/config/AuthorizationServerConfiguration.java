package com.demozi.oauth.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }



    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        //开放token检查端点 ，不拦截 /oauth/check_token， /oauth/token_key，资源服务器需要请求授权服务器完成token验证
        security.tokenKeyAccess("permitAll()")
                .checkTokenAccess("isAuthenticated()")
                .allowFormAuthenticationForClients();
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {

        /**
         * 内存级，第三应用信息。
         * clientId  账号
         * secret    密码
         * authorities 角色
         * scopes   授权范围
         * authorizedGrantTypes 认证模式
         * redirectUris 授权通过跳转路径
         *
         * 1. 授权请求地址： http://localhost:8081/oauth/authorize?client_id=clientId&response_type=code
         * 2. 授权通过后，返回：https://www.baidu.com/?code=ALzCtY
         *
         * 3.根据授权码，请求token
         * POST http://clientId:secret@localhost:8081/oauth/token  grant_type:authorization_code code:ALzCtY
         * 返回：
         * {
         *     "access_token": "e5822a49-1bd8-44a9-910e-07d59e72c5b1",
         *     "token_type": "bearer",
         *     "refresh_token": "fd7d6c68-f705-462d-81eb-0ecac190a081",
         *     "expires_in": 43199,
         *     "scope": "read write"
         * }
         *
         *
         */
        clients.inMemory()
                .withClient("clientId")
                .secret(passwordEncoder.encode("secret"))
                .authorities("ROLE_CLIENT")
                .scopes("read", "write")
                .authorizedGrantTypes("authorization_code", "refresh_token")
                .redirectUris("https://baidu.com");
    }
}
