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
        grantTypes.add("refresh_token");//配置了才会返回刷新token
        baseClientDetails.setAuthorizedGrantTypes(grantTypes);
        Set<String> redirectUri = new HashSet<>();
        redirectUri.add("https://www.baidu.com");
        baseClientDetails.setRegisteredRedirectUri(redirectUri);
        return baseClientDetails;
    }
}
