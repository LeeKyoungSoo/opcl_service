package com.lnworks.opcl.oauth.controller;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.lnworks.opcl.oauth.vo.TokenInfo;
import org.springframework.http.HttpHeaders;
import org.springframework.security.jwt.Jwt;

import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
public class ResourceController {
    @RequestMapping("/oauth/main")
    public Object oauthmain(HttpServletRequest request) {
        TokenInfo tokenInfo = getAccessTokenInfo(request);
        return tokenInfo;
    }

    public TokenInfo getAccessTokenInfo(HttpServletRequest request){
        TokenInfo tokenInfo = null;
        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        RemoteTokenServices remoteTokenService = new RemoteTokenServices();

       if ( StringUtils.startsWithIgnoreCase(authorization, "Bearer") ) {
            Jwt jwt = JwtHelper.decode(StringUtils.replace(authorization, "Bearer ",""));
            Gson gson = new GsonBuilder().setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES).create(); // snakecase to camelcase
            tokenInfo = gson.fromJson(jwt.getClaims(), TokenInfo.class);
        }
        return tokenInfo;
    }
}