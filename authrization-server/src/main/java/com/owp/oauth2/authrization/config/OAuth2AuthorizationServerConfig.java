package com.owp.oauth2.authrization.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Configuration
@EnableAuthorizationServer
public class OAuth2AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

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

    /**
     * 注意：这里不能使用接口引用，否则会导致自己引用自己，内存溢出
     * 解决办法：
     * 1.直接引用自己创建的类，而非父类
     * 2.给自己写的类命名一个别名，这里使用别名引用
     */
    @Autowired
    private OwpClientDetailsService clientDetailsService;

    /**
     * 在com.owp.oauth2.authrization.security.SecurityConfig中申明bean
     */
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private TokenStore tokenStore;

    @Autowired(required = false)
    private TokenEnhancer jwtTokenEnhancer;

    @Autowired(required = false)
    private JwtAccessTokenConverter jwtAccessTokenConverter;

    /**
     * 也可以直接使用框架自带的数据库方式，使用JdbcClientDetailsService，但是这种方式
     *
     * @param clients
     * @throws Exception
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.withClientDetails(clientDetailsService);
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.tokenStore(tokenStore)
                .authenticationManager(authenticationManager)
                .userDetailsService(userDetailsService);
        if (jwtAccessTokenConverter != null && jwtTokenEnhancer != null) {
            TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
            List<TokenEnhancer> enhancerList = new ArrayList();
            enhancerList.add(jwtTokenEnhancer);
            enhancerList.add(jwtAccessTokenConverter);
            tokenEnhancerChain.setTokenEnhancers(enhancerList);
            //jwt
            endpoints.tokenEnhancer(tokenEnhancerChain)
                    .accessTokenConverter(jwtAccessTokenConverter);
        }
    }

    /**
     * 指定密码编码格式，不设置会导致调用/oauth/token接口获取token报错401
     *
     * @param security
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
//        super.configure(security);
        // 认证服务器安全配置
        security.passwordEncoder(passwordEncoder).allowFormAuthenticationForClients();
    }
}
