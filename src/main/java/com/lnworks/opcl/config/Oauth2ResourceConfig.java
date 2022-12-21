package com.lnworks.opcl.config;

import com.google.gson.Gson;
import kong.unirest.JsonNode;
import kong.unirest.Unirest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@Configuration
public class Oauth2ResourceConfig extends ResourceServerConfigurerAdapter {

    // API 별 필요한 인증정보 설정
    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/main")
                .access("#oauth2.hasAnyScope('read')")
                .anyRequest()
                .authenticated();
    }

    // 토큰 유효성 체크 - JWT 에서는 사용 안함
    /*@Override
    public void configure(ResourceServerSecurityConfigurer resources) {
        RemoteTokenServices remoteTokenService = new RemoteTokenServices();
        remoteTokenService.setClientId("clientId");
        remoteTokenService.setClientSecret("secretKey");
        remoteTokenService.setCheckTokenEndpointUrl("http://localhost:8081/oauth/check_token");
        resources.tokenServices(remoteTokenService);
    }*/
}

