package com.lnworks.opcl.oauth.vo;

import lombok.Data;

import java.util.List;

@Data
public class TokenInfo {
    private String userName;
    private String corinNickName;
    private String corinId;
    private String clientId;
    private List<String> authorities;
}
