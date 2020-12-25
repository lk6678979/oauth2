package com.owp.oauth2.authrization.config;

import com.owp.oauth2.authrization.properties.OAuth2ClientProperties;
import com.owp.oauth2.authrization.properties.OAuth2Properties;
import org.apache.commons.lang.ArrayUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.builders.InMemoryClientDetailsServiceBuilder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;

@Configuration
@EnableAuthorizationServer
public class OAuth2AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
    /**
     * 客户端配置对象，读取yml中的client配置
     */
    @Autowired
    private OAuth2Properties oAuth2Properties;

    /**
     * 该对象用来支持 password 模式
     * 在com.owp.oauth2.authrization.security.SecurityConfig中申明bean
     * 注意自定义的SecurityConfig类需要继承WebSecurityConfigurerAdapter
     */
    @Autowired
    private AuthenticationManager authenticationManager;

    /**
     * 通过用户名来加载用户 。这个方法主要用于从系统数据中查询并加载具体的用户到Spring Security中
     * 具体如何加载用户可以自己实现
     */
    @Autowired
    private UserDetailsService userDetailsService;

//    @Autowired
//    private TokenStore tokenStore;

//    @Autowired(required = false)
//    private JwtAccessTokenConverter jwtAccessTokenConverter;
//
//    @Autowired(required = false)
//    private TokenEnhancer jwtTokenEnhancer;
//
    /**
     * 在com.owp.oauth2.authrization.security.SecurityConfig中申明bean
     */
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        InMemoryClientDetailsServiceBuilder build = clients.inMemory();
        if (ArrayUtils.isNotEmpty(oAuth2Properties.getClients())) {
            for (OAuth2ClientProperties config : oAuth2Properties.getClients()) {
                build.withClient(config.getClientId())
                        .secret(passwordEncoder.encode(config.getClientSecret()))
                        .accessTokenValiditySeconds(config.getAccessTokenValiditySeconds())
                        .refreshTokenValiditySeconds(60 * 60 * 24 * 15)
                        //.authorizedGrantTypes("refresh_token", "password", "authorization_code")//OAuth2支持的验证模式
                        .authorizedGrantTypes("authorization_code")//OAuth2支持的验证模式
                        .redirectUris("https://www.baidu.com")//指定回调URI，客户端提交请求时，必须保持一致
                        .scopes("all");
            }
        }
    }
}
