package com.lnworks.opcl.config;

import com.lnworks.opcl.oauth.service.UserDetailService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class WebMvcConfig {

    // bean 에 등록하여 직접 구현한 서비스를 기본 서비스로 사용
    // 이미 빈이 생성되어 있기에 application.yml에
    // spring.main.allow-bean-definition-overriding 값을 true 로 하여 선언한 빈으로 설정 되도록 한다.
    @Bean
    public UserDetailService userDetailService(){
        return new UserDetailService();
    }
}