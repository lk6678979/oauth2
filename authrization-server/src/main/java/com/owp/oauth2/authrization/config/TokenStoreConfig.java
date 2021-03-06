package com.owp.oauth2.authrization.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;

import javax.sql.DataSource;

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
}
