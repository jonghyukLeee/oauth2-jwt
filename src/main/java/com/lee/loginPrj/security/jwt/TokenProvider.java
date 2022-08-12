package com.lee.loginPrj.security.jwt;

import com.lee.loginPrj.domain.user.UserRepository;
import com.lee.loginPrj.security.auth.user.CustomOAuth2User;
import com.lee.loginPrj.util.RedisService;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletResponse;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Component
public class TokenProvider {

    private static final Logger log = LoggerFactory.getLogger(TokenProvider.class);
    private final RedisService redisService;

    @Value("${app.auth.tokenExpiration}")
    private long TOKEN_EXPIRATION;

    @Value("${app.auth.token.tokenSecret}")
    private String TOKEN_SECRET;

    public String createAccessToken(Authentication authentication) {
        CustomOAuth2User user = (CustomOAuth2User) authentication.getPrincipal();

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + TOKEN_EXPIRATION); // 30분

        // 유저 권한
        String role = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        //토큰 빌드
        return Jwts.builder()
                .signWith(SignatureAlgorithm.HS512, TOKEN_SECRET)
                .setSubject(Long.toString(user.getId()))
                .claim("role",role)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .compact();
    }

    public void createRefreshToken(Authentication authentication, HttpServletResponse response) {

        Date now = new Date();
        long refreshExpiration = TOKEN_EXPIRATION * 24;
        Date expiryDate = new Date(now.getTime() + refreshExpiration); // 1일

        //토큰 빌드
        String refreshToken =
                Jwts.builder()
                .signWith(SignatureAlgorithm.HS512, TOKEN_SECRET)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .compact();

        // Redis 저장소에 refreshToken 저장
        CustomOAuth2User user = (CustomOAuth2User) authentication.getPrincipal();
        redisService.setValues(Long.toString(user.getId()), refreshToken, Duration.ofDays(1));

        // ResponseCookie 생성
        ResponseCookie cookie = ResponseCookie.from("refresh", refreshToken)
                .httpOnly(true)
                .secure(true)
                .sameSite("Lax")
                .maxAge(refreshExpiration)
                .path("/")
                .build();

        //응답헤더에 쿠키 add
        response.addHeader("SET-COOKIE",cookie.toString());
    }

    //AccessToken 을 검사하고 Authentication 객체 생성
    //@AuthenticationPrincipal 로 컨트롤러에서 꺼내쓸수있음
    public Authentication getAuthentication(String accessToken) {
        Claims claims = parseClaims(accessToken);

        Collection<? extends GrantedAuthority> authorities = Arrays.stream(claims.get("role").toString().split(","))
                .map(SimpleGrantedAuthority::new).collect(Collectors.toList());

        CustomOAuth2User principal = new CustomOAuth2User(Long.valueOf(claims.getSubject()),"",authorities);
        return new UsernamePasswordAuthenticationToken(principal,"",authorities);
    }

    // AccessToken 만료 시, 갱신때 사용할 정보를 얻기 위해 Claim 리턴
    private Claims parseClaims(String accessToken) {
        try {
            return Jwts.parser().setSigningKey(TOKEN_SECRET).parseClaimsJws(accessToken).getBody();
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }
    }

    // Access Token 검증
    public Boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(TOKEN_SECRET).parseClaimsJws(token);
            return true;
        } catch (ExpiredJwtException e) {
            log.info("만료된 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            log.info("지원되지 않는 토큰입니다.");
        } catch (IllegalStateException e) {
            log.info("잘못된 토큰입니다.");
        }
        return false;
    }
}
