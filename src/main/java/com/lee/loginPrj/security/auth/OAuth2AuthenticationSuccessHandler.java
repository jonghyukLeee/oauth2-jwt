package com.lee.loginPrj.security.auth;

import com.lee.loginPrj.exception.BadRequestException;
import com.lee.loginPrj.security.jwt.TokenProvider;
import com.lee.loginPrj.util.CookieUtil;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.Optional;

import static com.lee.loginPrj.security.auth.CookieAuthorizationRequestRepository.REDIRECT_URI_PARAM_COOKIE_NAME;

@RequiredArgsConstructor
@Component
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final Logger log = LoggerFactory.getLogger(OAuth2AuthenticationSuccessHandler.class);
    private final CookieAuthorizationRequestRepository authorizationRequestRepository;
    private final TokenProvider tokenProvider;
    @Value("${app.oauth2.redirectUri")
    private String REDIRECT_URI;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        String targetUri = determineTargetUrl(request, response, authentication);

        if (response.isCommitted()) {
            log.debug("Response has already been committed");
            return;
        }

        // CookieAuthorizationRequestRepository 비우고
        clearAuthenticationAttributes(request, response);
        getRedirectStrategy().sendRedirect(request, response, targetUri);
    }

    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        // 요청 쿠키에서 redirectUri 추출
        Optional<String> redirectUri = CookieUtil.getCookie(request,REDIRECT_URI_PARAM_COOKIE_NAME)
                .map(Cookie::getValue);

        // 설정된 redirectUri와 현재 요청 uri와 비교
        if(redirectUri.isPresent() && !isAuthorizedRedirectUri(redirectUri.get())) {
            throw new BadRequestException("일치하지 않는 redirectUri 입니다.");
        }
        String targetUri = redirectUri.orElse(getDefaultTargetUrl());

        //Access Token 생성
        String accessToken = tokenProvider.createAccessToken(authentication);
        //Refresh Token 생성
        tokenProvider.createRefreshToken(authentication, response);

        //Access Token 은 body에 담아서 보냄 (클라이언트 로컬 저장소 활용)
        return UriComponentsBuilder.fromUriString(targetUri)
                .queryParam("accessToken",accessToken)
                .build().toUriString();
    }

    protected void clearAuthenticationAttributes(HttpServletRequest request, HttpServletResponse response) {
        super.clearAuthenticationAttributes(request);

        // URI 검증을 마쳤으므로 authorizationRequestRepository 에서 쿠키정보 삭제
        authorizationRequestRepository.removeAuthorizationRequestCookies(request,response);
    }

    private boolean isAuthorizedRedirectUri(String uri) {
        URI clientRedirectUri = URI.create(uri);
        URI authorizedUri = URI.create(REDIRECT_URI);

        // host , port만 비교 (CSRF)
        return authorizedUri.getHost().equalsIgnoreCase(clientRedirectUri.getHost())
                && authorizedUri.getPort() == clientRedirectUri.getPort();
    }
}
