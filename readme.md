# 授权服务器
OAuth 2 标准中定义了以下几种角色：  
* 资源所有者（Resource Owner）：即代表授权客户端访问本身资源信息的用户，客户端访问用户帐户的权限仅限于用户授权的“范围”。
* 客户端（Client）：即代表意图访问受限资源的第三方应用。在访问实现之前，它必须先经过用户者授权，并且获得的授权凭证将进一步由授权服务器进行验证。
* 授权服务器（Authorization Server）：授权服务器用来验证用户提供的信息是否正确，并返回一个令牌给第三方应用。
* 资源服务器（Resource Server）：资源服务器是提供给用户资源的服务器，例如头像、照片、视频等

OAuth 协议的授权模式共分为 4 种，分别说明如下：
* 授权码模式(authorization_code)：授权码模式（authorization code）是功能最完整、流程最严谨的授权模式。它的特点就是通过客户端的服务器与授权服务器进行交互，国内常见的第三方平台登录功能基本 都是使用这种模式。
* 简化模式：简化模式不需要客户端服务器参与，直接在浏览器中向授权服务器中请令牌，一般若网站是纯静态页面，则可以采用这种方式。
* 密码模式(password)：密码模式是用户把用户名密码直接告诉客户端，客户端使用这些信息向授权服务器中请令牌。这需要用户对客户端高度信任，例如客户端应用和服务提供商是同一家公司。
* 客户端模式：客户端模式是指客户端使用自己的名义而不是用户的名义向服务提供者申请授权。严格来说，客户端模式并不能算作 OAuth 协议要解决的问题的一种解决方案，但是，对于开发者而言，在一些前后端分离应用或者为移动端提供的认证授权服务器上使用这种模式还是非常方便的。

## 1. 授权服务器
### 1.1. 编写SecurityConfig配置类
* 继承WebSecurityConfigurerAdapter
* 申明AuthenticationManager
* 申明PasswordEncoder
```yaml
package com.owp.oauth2.authrization.security;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        AuthenticationManager manager = super.authenticationManagerBean();
        return manager;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .formLogin().and()
                //.httpBasic().and()
                // .antMatcher("user/login").anonymous().and()
                .csrf().disable();
    }
}
```
### 1.2. 编写用户详细信息服务类
```yaml
package com.owp.oauth2.authrization.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * 用户详细信息服务
 * 通过用户名来加载用户 。这个方法主要用于从系统数据中查询并加载具体的用户到Spring Security中
 */
@Component
public class OwpUserDetailsService implements UserDetailsService {

    @Autowired
    private PasswordEncoder passwordEncoder;

    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //TODO 这样可以自行实现加载方式，例如从数据库中读取，这里为了方便测试，将密码设置为和密码一样
        List<GrantedAuthority> role_user = AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER");
        return new User(username, passwordEncoder.encode(username), role_user);
    }
}
```
### 1.3. 编写客户端详细信息服务类
```yaml
package com.owp.oauth2.authrization.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Component
public class OwpClientDetailsService implements ClientDetailsService {
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public ClientDetails loadClientByClientId(String s) throws ClientRegistrationException {
        //TODO 这样可以自行实现加载方式，例如从数据库中读取
        BaseClientDetails baseClientDetails = new BaseClientDetails();
        baseClientDetails.setClientId("user_one");
        baseClientDetails.setClientSecret(passwordEncoder.encode("user_one_secret"));
        List<String> scopes = new ArrayList<>();
        scopes.add("all");
        baseClientDetails.setScope(scopes);
        baseClientDetails.setRefreshTokenValiditySeconds(7200);
        List<String> grantTypes = new ArrayList<>();
        grantTypes.add("authorization_code");
        baseClientDetails.setAuthorizedGrantTypes(grantTypes);
        Set<String> redirectUri = new HashSet<>();
        redirectUri.add("https://www.baidu.com");
        baseClientDetails.setRegisteredRedirectUri(redirectUri);
        return baseClientDetails;
    }
}
```

### 1.2. 一个简单的配置授权服务器
创建一个自定义类继承自 AuthorizationServerConfigurerAdapter，完成对授权服务器的配置，然后通过 @EnableAuthorizationServer 注解开启授权服务器：
```yaml
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
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;

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

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.withClientDetails(clientDetailsService);
    }
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.tokenStore(new InMemoryTokenStore())
                .authenticationManager(authenticationManager)
                .userDetailsService(userDetailsService);
    }

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
```
在浏览器测试：
http://localhost:8888/oauth/authorize?client_id=user_one&response_type=code&redirect_uri=https://www.baidu.com
进入用户登录界面
![](https://github.com/lk6678979/image/blob/master/oauth2-login-1.jpg)  
登录后显示是否授权
![](https://github.com/lk6678979/image/blob/master/oauth2-login-2.jpg)  
选择授权跳转到回调url，url后面有code
![](https://github.com/lk6678979/image/blob/master/oauth2-login-3.jpg)  
拿到这个授权码(code)去交换 access_token  
认证服务器核对了授权码和重定向URI，确认无误后，向客户端发送访问令牌（access token）和更新令牌（refresh token）
![](https://github.com/lk6678979/image/blob/master/oauth2-login-4.jpg)  
### 1.2. 设置TOKEN的存储方式
在上面的例子中，我们采用内存存储TOKEN，在集群情况下会出现无法获取TOKEN的问题，那么就需要以JVM外部的一个单独空间存储，一般说REDIS和MYSQL
### 1.2.1 申明REDIS和JDBC两种方式的TokenStore
```yaml
    @Autowired
    private RedisConnectionFactory redisConnectionFactory;

    @Autowired
    private DataSource dataSource;

    /**
     * Token存储Redis
     */
    @Bean
    @ConditionalOnProperty(prefix = "owp.security.oauth2", name = "storeType", havingValue = "redis")
    public TokenStore redisTokenStore() {
        return new RedisTokenStore(redisConnectionFactory);
    }

    /**
     * Token存储jdbc
     * 框架已提前为我们设计好了数据库表，但对于 MYSQL 来说，默认建表语句中主键为 Varchar(256)，
     * 这超过了最大的主键长度，可改成 128，并用 BLOB 替换语句中的 LONGVARBINARY 类型
     * 建表语句：
     * https://github.com/spring-projects/spring-security-oauth/blob/master/spring-security-oauth2/src/test/resources/schema.sql
     *
     */
    @Bean
    @ConditionalOnProperty(prefix = "owp.security.oauth2", name = "storeType", havingValue = "jdbc")
    public TokenStore jdbcTokenStore() {
        return new JdbcTokenStore(dataSource);
    }
```
### 1.2.1 配置TokenStore
```yaml
    @Autowired
    private TokenStore tokenStore;

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.tokenStore(tokenStore)
                .authenticationManager(authenticationManager)
                .userDetailsService(userDetailsService);
    }
```
### 1.2.1 测试
* 用上面同样的方式去获取TOKEN，REDIS中的存储结构：
![](https://github.com/lk6678979/image/blob/master/oauth2-login-5.jpg)  
* 用上面同样的方式去获取TOKEN，MYSQL中的存储结构：
![](https://github.com/lk6678979/image/blob/master/oauth2-login-6.jpg)  