package com.owp.oauth2.authrization.properties;

import lombok.Data;

@Data
public class OAuth2ClientProperties {

    private String clientId;

    private String clientSecret;

    private Integer accessTokenValiditySeconds = 7200;
}
