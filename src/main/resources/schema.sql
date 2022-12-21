-- 서비스 사용자
-- state [ Y : 정상 회원 , L : 잠긴 계정, P : 패스워드 만료, A : 계정 만료]
CREATE TABLE IF NOT EXISTS user (
    id          varchar(20),
    password    varchar(100),
    nickname    varchar(100),
    state       char(1),
    PRIMARY KEY (id)
);

-- access token 저장 > jwt 아닐때 유효 토큰 검증시 사용
CREATE TABLE IF NOT EXISTS oauth_access_token
(
    token_id          VARCHAR(256) NULL,
    token             BLOB         NULL,
    authentication_id VARCHAR(256) NOT NULL,
    user_name         VARCHAR(256) NULL,
    client_id         VARCHAR(256) NULL,
    authentication    BLOB         NULL,
    refresh_token     VARCHAR(256) NULL,
    PRIMARY KEY (authentication_id)
);

-- refresh token 저장 > jwt 아닐때 유효 토큰 검증시 사용
CREATE TABLE IF NOT EXISTS oauth_refresh_token
(
    token_id        VARCHAR(256) NULL,
    token           BLOB         NULL,
    authentication  BLOB         NULL
);

-- 클라이언트 정보 테이블
CREATE TABLE IF NOT EXISTS oauth_client_details
(
    client_id                   VARCHAR(256)  NOT NULL,
    resource_ids                VARCHAR(256)  NULL,
    client_secret               VARCHAR(256)  NULL,
    scope                       VARCHAR(256)  NULL,
    authorized_grant_types      VARCHAR(256)  NULL,
    web_server_redirect_uri     VARCHAR(256)  NULL,
    authorities                 VARCHAR(256)  NULL,
    access_token_validity       INT           NULL,
    refresh_token_validity      INT           NULL,
    additional_information      VARCHAR(4096) NULL,
    autoapprove                 VARCHAR(256)  NULL,
    PRIMARY KEY (client_id)
);

-- 권한 관리 테이블
CREATE TABLE IF NOT EXISTS oauth_approvals
(
    userId          VARCHAR(256),
    clientId        VARCHAR(256),
    scope           VARCHAR(256),
    status          VARCHAR(10),
    expiresAt       TIMESTAMP,
    lastModifiedAt  TIMESTAMP
);

-- 클라이언트 정보 등록 쿼리
--INSERT INTO oauth_client_details (
--    client_id,
--    resource_ids,
--    client_secret,
--    scope,
--    authorized_grant_types,
--    web_server_redirect_uri,
--    authorities,
--    access_token_validity,
--    refresh_token_validity,
--    additional_information,
--    autoapprove
--) VALUES (
--     'clientId',
--     null, -- 해당 클라이언트가 특정 리소스 서버에만 접속하기를 원할 경우 사용
--     '{noop}secretKey',
--     'read, write',
--     'authorization_code,implicit,password,client_credentials,refresh_token',
--     'http://localhost:8081/callback',
--     'TEST_ROLE',
--     60,
--     3600,
--     null ,
--     'false' -- 설정은 true 했었지만 권한 동의 화면도 구성할것이기에 false 로 하여 권한 동의 화면을 띄운다.
--);
