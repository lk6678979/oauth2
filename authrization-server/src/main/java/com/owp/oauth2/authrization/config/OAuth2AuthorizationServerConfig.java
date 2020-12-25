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
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;

import java.util.ArrayList;
import java.util.List;

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
//
//    @Autowired
//    private TokenStore tokenStore;
//
//    @Autowired(required = false)
//    private JwtAccessTokenConverter jwtAccessTokenConverter;
//
//    @Autowired(required = false)
//    private TokenEnhancer jwtTokenEnhancer;

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
//    @Override
//    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
//        endpoints.tokenStore(new InMemoryTokenStore())
//                .authenticationManager(authenticationManager)
//                .userDetailsService(userDetailsService);
//        //扩展token返回结果
////        if (jwtAccessTokenConverter != null && jwtTokenEnhancer != null) {
////            TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
////            List<TokenEnhancer> enhancerList = new ArrayList();
////            enhancerList.add(jwtTokenEnhancer);
////            enhancerList.add(jwtAccessTokenConverter);
////            tokenEnhancerChain.setTokenEnhancers(enhancerList);
////            //jwt
////            endpoints.tokenEnhancer(tokenEnhancerChain)
////                    .accessTokenConverter(jwtAccessTokenConverter);
////        }
//    }

    /**
     * 指定密码编码格式，不设置会导致调用/oauth/token接口获取token报错401
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
