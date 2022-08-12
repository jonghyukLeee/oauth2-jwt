package com.lee.loginPrj.security.jwt;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 모든 Request에서 JWT 토큰을 검사하는 필터
 * Http Request Header에 Authorization : Bearer <JWT> 형태로 전송된 AccessToken을 검사하고,
 * 유효한다면 Authentication 객체를 SecurityContext에 저장한다.
 */
@RequiredArgsConstructor
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private final TokenProvider tokenProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String token = parseBearerToken(request);

        //Access Token 검사
        if (StringUtils.hasText(token) && tokenProvider.validateToken(token)) {
            //Authentication 객체 생성
            Authentication authentication = tokenProvider.getAuthentication(token);
            // SecurityContextHolder의 SecurityContext에 Authentication 객체 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);
            log.debug(authentication.getName() + "의 인증정보 저장");
        } else {
            log.debug("유효한 토큰이 없습니다.");
        }

        filterChain.doFilter(request,response);
    }

    private String parseBearerToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");

        //Access Token 파싱
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }


}
