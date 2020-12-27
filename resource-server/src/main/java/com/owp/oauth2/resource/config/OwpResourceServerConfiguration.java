package com.owp.oauth2.resource.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;

@Configuration
@EnableResourceServer
public class OwpResourceServerConfiguration extends ResourceServerConfigurerAdapter {

    @Autowired
    private TokenStore tokenStore;

    @Value("${owp.security.oauth2.resourceId}")
    private String resourceId;

    @Autowired
    private RemoteTokenServices remoteTokenServices;

    @Override
    public void configure(HttpSecurity http) throws Exception {
        /*
    	 注意：
    	 1、必须先加上： .requestMatchers().antMatchers(...)，表示对资源进行保护，也就是说，在访问前要进行OAuth认证。
    	 2、接着：访问受保护的资源时，要具有哪里权限。
    	 ------------------------------------
    	 否则，请求只是被Security的拦截器拦截，请求根本到不了OAuth2的拦截器。
    	 同时，还要注意先配置：security.oauth2.resource.filter-order=3，否则通过access_token取不到用户信息。
    	 ------------------------------------
    	 requestMatchers()部分说明：
    	 Invoking requestMatchers() will not override previous invocations of ::
    	 mvcMatcher(String)}, requestMatchers(), antMatcher(String), regexMatcher(String), and requestMatcher(RequestMatcher).
    	 */
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .and()
                //请求权限配置
                .authorizeRequests()
                //下边的路径放行,不需要经过认证
                .antMatchers("/oauth/*", "/auth/user/login").permitAll()
                //OPTIONS请求不需要鉴权
                .antMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                //private和protected接口需要保护
                //在实际使用中，我们可以将一个接口映射为一个scop，然后指定一定的规则，就可以做到限制用户使用的接口了
                //然后在这边将每一个接口和scop都加进来，当然你也可以用自定义注解更方便的进行接口说scope定义
                .antMatchers("/private/**", "/protected/**").access("#oauth2.hasScope('all')")
                .antMatchers("/private/**", "/protected/**").hasAuthority("ROLE_USER")
                //其余接口没有角色限制，但需要经过认证，只要携带token就可以放行
                .anyRequest()
                .authenticated();
    }

//    @Override
//    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
//        resources.tokenStore(tokenStore).resourceId(resourceId);
//    }

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        resources.tokenServices(remoteTokenServices).resourceId(resourceId);
    }

}
