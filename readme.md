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
* 在浏览器测试：
http://localhost:8888/oauth/authorize?client_id=user_one&response_type=code&redirect_uri=https://www.baidu.com
* 进入用户登录界面
![](https://github.com/lk6678979/image/blob/master/oauth2-login-1.jpg)  
* 登录后显示是否授权
![](https://github.com/lk6678979/image/blob/master/oauth2-login-2.jpg)  
* 选择授权跳转到回调url，url后面有code
![](https://github.com/lk6678979/image/blob/master/oauth2-login-3.jpg)  
* 拿到这个授权码(code)去交换 access_token,认证服务器核对了授权码和重定向URI，确认无误后，向客户端发送访问令牌（access token）和更新令牌（refresh token）
![](https://github.com/lk6678979/image/blob/master/oauth2-login-4.jpg)  
### 1.2. 设置TOKEN的存储方式
* 在上面的例子中，我们采用内存存储TOKEN，在集群情况下会出现无法获取TOKEN的问题，那么就需要以JVM外部的一个单独空间存储，一般说REDIS和MYSQL
* 在上面的例子中，我们采用内存存储TOKEN，在集群情况下会出现无法获取TOKEN的问题，那么就需要以JVM外部的一个单独空间存储，一般说REDIS和MYSQL
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
### 1.3. 使用JWT
#### 1.3.1  编写JWT拓展类（也可以不用）
```yaml
package com.owp.oauth2.authrization.config;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

import java.util.HashMap;
import java.util.Map;

/**
 * 自定义拓展JWT，也就是额外写入kv到jwt中
 */
public class OwpJwtTokenEnhancer implements TokenEnhancer {

    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
        Map<String, Object> info = new HashMap<String, Object>();
        info.put("organization", authentication.getName() + "_"+System.currentTimeMillis());
        ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(info);
        return accessToken;
    }
}
```
#### 1.3.2  编写JWT的TokenStore-对称密钥
```yaml
/**
     * JWT-TOKEN配置信息,使用对称加密
     */
    @Configuration
    @ConditionalOnProperty(prefix = "owp.security.oauth2", name = "storeType", havingValue = "jwt-key", matchIfMissing = true)
    public static class JwtTokenConfig {
        @Value("${owp.security.oauth2.jwtSigningKey:owpSigningKey}")
        private String jwtSigningKey;

        /**
         * 使用jwtTokenStore存储token
         *
         * @return
         */
        @Bean
        public TokenStore jwtTokenStore() {
            return new JwtTokenStore(jwtAccessTokenConverter());
        }

        /**
         * 用于生成jwt
         *
         * @return
         */
        @Bean
        public JwtAccessTokenConverter jwtAccessTokenConverter() {
            JwtAccessTokenConverter accessTokenConverter = new JwtAccessTokenConverter();
            accessTokenConverter.setSigningKey(jwtSigningKey);//生成签名的key
            return accessTokenConverter;
        }

        /**
         * 用于扩展JWT,自定义令牌声明，添加额外的属性
         *
         * @return
         */
        @Bean
        @ConditionalOnMissingBean(name = "jwtTokenEnhancer")
        public TokenEnhancer jwtTokenEnhancer() {
            return new OwpJwtTokenEnhancer();
        }
    }
```
#### 1.3.2  编写JWT的TokenStore-非对称密钥
```yaml
/**
     * JWT-TOKEN配置信息,使用非对称加密
     */
    @Configuration
    @ConditionalOnProperty(prefix = "owp.security.oauth2", name = "storeType", havingValue = "jwt-rsa", matchIfMissing = true)
    public static class JwtTokenRsaConfig {
        @Value("${owp.security.oauth2.jwtSigningJsk:/data/rsa/jdk/keystore.jks}")
        private String jwtSigningJsk;

        @Value("${owp.security.oauth2.jwtSigningJskPwd:123456}")
        private String jwtSigningJskPwd;

        /**
         * 使用jwtTokenStore存储token
         *
         * @return
         */
        @Bean
        public TokenStore jwtTokenStore() {
            return new JwtTokenStore(jwtAccessTokenConverter());
        }

        /**
         * 用于生成jwt
         *
         * @return
         */
        @Bean
        public JwtAccessTokenConverter jwtAccessTokenConverter() {
            JwtAccessTokenConverter accessTokenConverter = new JwtAccessTokenConverter();
            KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(new ClassPathResource(jwtSigningJsk), jwtSigningJskPwd.toCharArray());
            accessTokenConverter.setKeyPair(keyStoreKeyFactory.getKeyPair("jwtSigning"));
            return accessTokenConverter;
        }

        /**
         * 用于扩展JWT,自定义令牌声明，添加额外的属性
         *
         * @return
         */
        @Bean
        @ConditionalOnMissingBean(name = "jwtTokenEnhancer")
        public TokenEnhancer jwtTokenEnhancer() {
            return new OwpJwtTokenEnhancer();
        }
    }
```
#### 1.3.3  修改配置
```yaml
    @Autowired(required = false)
    private TokenEnhancer jwtTokenEnhancer;

    @Autowired(required = false)
    private JwtAccessTokenConverter jwtAccessTokenConverter;
    
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
```
* 用上面同样的方式去获取JWT：
![](https://github.com/lk6678979/image/blob/master/oauth2-login-7.jpg)  
#### 我们还可以自定义登录页面、登录成功和登录失败处理方法，具体如何实现请百度
ResourceServerSecurityConfigurer 可配置属性
* tokenServices：ResourceServerTokenServices 类的实例，用来实现令牌业务逻辑服务
* resourceId：这个资源服务的ID，这个属性是可选的，但是推荐设置并在授权服务中进行验证
* tokenExtractor 令牌提取器用来提取请求中的令牌
* 请求匹配器，用来设置需要进行保护的资源路径，默认的情况下是受保护资源服务的全部路径
* 受保护资源的访问规则，默认的规则是简单的身份验证（plain authenticated）
* 其他的自定义权限保护规则通过 HttpSecurity 来进行配置

## 1.3. 一个简单的资源服务器（本地校验）
可以选择本地验证token并获取相关信息，也可以远程从授权服务器获取
#### 1.3.1 添加本地验证token的TokenStore
这里和授权服务器一样，配置对应的TokenStore机制，代码也基本一样
```yaml
package com.owp.oauth2.resource.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;

import javax.sql.DataSource;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.stream.Collectors;

@Configuration
public class TokenStoreConfig {

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
     */
    @Bean
    @ConditionalOnProperty(prefix = "owp.security.oauth2", name = "storeType", havingValue = "jdbc")
    public TokenStore jdbcTokenStore() {
        return new JdbcTokenStore(dataSource);
    }

    /**
     * JWT-TOKEN配置信息,使用对称加密
     */
    @Configuration
    @ConditionalOnProperty(prefix = "owp.security.oauth2", name = "storeType", havingValue = "jwt-key", matchIfMissing = true)
    public static class JwtTokenConfig {
        @Value("${owp.security.oauth2.jwtSigningKey:owpSigningKey}")
        private String jwtSigningKey;

        /**
         * 使用jwtTokenStore存储token
         *
         * @return
         */
        @Bean
        public TokenStore jwtTokenStore() {
            return new JwtTokenStore(jwtAccessTokenConverter());
        }

        /**
         * 用于生成jwt
         *
         * @return
         */
        @Bean
        public JwtAccessTokenConverter jwtAccessTokenConverter() {
            JwtAccessTokenConverter accessTokenConverter = new JwtAccessTokenConverter();
            accessTokenConverter.setSigningKey(jwtSigningKey);//生成签名的key
            return accessTokenConverter;
        }

    }

    /**
     * JWT-TOKEN配置信息,使用非对称加密
     */
    @Configuration
    @ConditionalOnProperty(prefix = "owp.security.oauth2", name = "storeType", havingValue = "jwt-rsa", matchIfMissing = true)
    public static class JwtTokenRsaConfig {
        @Value("${owp.security.oauth2.jwtSigningPublic}")
        private String jwtSigningPublic;

        @Value("${owp.security.oauth2.jwtSigningJskPwd:123456}")
        private String jwtSigningJskPwd;

        /**
         * 使用jwtTokenStore存储token
         *
         * @return
         */
        @Bean
        public TokenStore jwtTokenStore() {
            return new JwtTokenStore(jwtAccessTokenConverter());
        }

        /**
         * 用于生成jwt
         *
         * @return
         */
        @Bean
        public JwtAccessTokenConverter jwtAccessTokenConverter() {
            JwtAccessTokenConverter accessTokenConverter = new JwtAccessTokenConverter();
            //设置用于解码的非对称加密的公钥
            accessTokenConverter.setVerifierKey(jwtSigningPublic);
            return accessTokenConverter;
        }
    }
}
```
#### 1.3.2 配置资源服务器
```yaml
package com.owp.oauth2.resource.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;

@Configuration
@EnableResourceServer
public class OwpResourceServerConfiguration extends ResourceServerConfigurerAdapter {

    @Autowired
    private TokenStore tokenStore;

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
                .antMatchers("/private/**", "/protected/**").access("#oauth2.hasScope('all2')")
                .antMatchers("/private/**", "/protected/**").hasAuthority("ROLE_USER2")
                //其余接口没有角色限制，但需要经过认证，只要携带token就可以放行
                .anyRequest()
                .authenticated();
    }

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        resources.tokenStore(tokenStore);
    }
}
```
#### 1.3.2 在资源服务器中编写一个测试api
```yaml
    @GetMapping(value = "private/api")
    public String success() {
        return "SUCCESS";
    }
```
* 使用token调用接口
* 如果token校验没有接口权限：
![](https://github.com/lk6678979/image/blob/master/oauth2-login-8.jpg)  
* 有权限则正常返回
![](https://github.com/lk6678979/image/blob/master/oauth2-login-9.jpg) 
## 1.4. 一个简单的资源服务器（远程校验）
也可以远程从授权服务器获取
#### 1.4.1 添加远程校验Token服务
```yaml
    @Value("${owp.security.oauth2.serverUrl:http://127.0.0.1:8888/oauth}")
    private String serverUrl;
    @Value("${owp.security.oauth2.clientId}")
    private String clientId;
    @Value("${owp.security.oauth2.clientSecret}")
    private String clientSecret;
    
        @Bean
        public RemoteTokenServices remoteTokenServices() {
            StringBuilder serverUrlBuilder = new StringBuilder();
            final RemoteTokenServices tokenServices = new RemoteTokenServices();
            tokenServices.setCheckTokenEndpointUrl(serverUrlBuilder.append(serverUrl).append("/check_token").toString());
            tokenServices.setClientId(clientId);
            tokenServices.setClientSecret(clientSecret);
            return tokenServices;
        }
```
#### 1.4.1 配置使用远程Token校验代替TokenStore
```yaml
    @Value("${owp.security.oauth2.resourceId}")
    private String resourceId;
    
    @Autowired
    private RemoteTokenServices remoteTokenServices;
        
    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        resources.tokenServices(remoteTokenServices).resourceId(resourceId);
    }
```