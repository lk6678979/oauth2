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
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;
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

    @Value("${owp.security.oauth2.serverUrl:http://127.0.0.1:8888/oauth}")
    private String serverUrl;
    @Value("${owp.security.oauth2.clientId}")
    private String clientId;
    @Value("${owp.security.oauth2.clientSecret}")
    private String clientSecret;

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

    @Bean
    public RemoteTokenServices remoteTokenServices() {
        StringBuilder serverUrlBuilder = new StringBuilder();
        final RemoteTokenServices tokenServices = new RemoteTokenServices();
        tokenServices.setCheckTokenEndpointUrl(serverUrlBuilder.append(serverUrl).append("/check_token").toString());
        tokenServices.setClientId(clientId);
        tokenServices.setClientSecret(clientSecret);
        return tokenServices;
    }
}
