package com.example.jwt.config;

import com.example.jwt.login.jwt.exception.RestAuthenticationEntryPoint;
import com.example.jwt.login.jwt.handler.TokenAccessDeniedHandler;
import com.example.jwt.oauth.RoleType;
import com.example.jwt.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsUtils;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class AuthencationConfig {

    private final UserService userService;
    private final TokenAccessDeniedHandler tokenAccessDeniedHandler;
    @Value("${jwt.secret}")
    private String secretKey;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // session을 사용하지 않을 것이기 때문에 stateless 설정 추가
                .and()
                .csrf()
                .disable() // csrf 설정 해제
                .formLogin().disable() // 소셜로그인만 이용할 것이기 때문에 formLogin 해제
                .httpBasic().disable()
                .exceptionHandling()
                .authenticationEntryPoint(new RestAuthenticationEntryPoint()) // 요청이 들어올 시, 인증 헤더를 보내지 않는 경우 401 응답 처리
                .accessDeniedHandler(tokenAccessDeniedHandler)
                .and()
                .cors().and()
                .authorizeRequests()
                .requestMatchers(CorsUtils::isPreFlightRequest).permitAll() // cors 요청 허용
                .antMatchers("/", "/api/v1/users/join", "/api/v1/users/login").permitAll()
                .antMatchers("/api/v1/reviews").hasAnyAuthority(RoleType.USER.getCode(), RoleType.ADMIN.getCode())
                .antMatchers(HttpMethod.POST, "/api/v1/**").authenticated()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilterBefore(new JwtFilter(userService, secretKey), UsernamePasswordAuthenticationFilter.class)
                .build();
    }


}
