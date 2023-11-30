package com.example.jwt.config;

import com.example.jwt.oauth.RoleType;
import com.example.jwt.service.UserService;
import com.example.jwt.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

@Slf4j
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final UserService userService;
    private final String secretKey;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        final String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        log.info("authorization : {} ", authorization);

        if(authorization == null || !authorization.startsWith("Bearer ")){
            log.info("authorization을 잘못 요청 하셨습니다.");
            filterChain.doFilter(request, response);
            return;
        }

        //get token
        String token = authorization.split(" ")[1];
        log.info("token -- > : {}", token);

        //check expired token
        if(JwtUtil.isExpried(token, secretKey)){
            log.error("token is expried");
            filterChain.doFilter(request, response);
            return;
        }


        //Get userName
        String userName = JwtUtil.getUserName(token, secretKey);
        log.info("userName --> : {}", userName);

        //권한 부여
        UsernamePasswordAuthenticationToken authenticationToken
                = new UsernamePasswordAuthenticationToken(userName, null, List.of(new SimpleGrantedAuthority(RoleType.ADMIN.getCode())));

        //Set Detail
        authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        filterChain.doFilter(request, response);

    }
}
