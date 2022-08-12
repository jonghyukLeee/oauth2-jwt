package com.lee.loginPrj.security.auth.user;

import com.lee.loginPrj.domain.user.User;
import lombok.Builder;
import lombok.Getter;

import java.util.Map;

@Getter
public class OAuthAttributes {

    private String authId;
    private String name;
    private String email;

    @Builder
    public OAuthAttributes(String authId, String name, String email) {
        this.authId = authId;
        this.name = name;
        this.email = email;
    }

    public static OAuthAttributes of(String provider, String userNameAttributeName, Map<String, Object> attributes) {
        if (provider.equals("google")) return ofGoogle(attributes, createAuthId(attributes, provider, userNameAttributeName));
        else if (provider.equals("kakao")) return ofKakao(attributes, createAuthId(attributes, provider, userNameAttributeName));
        else if (provider.equals("naver"))  return ofNaver(attributes, createAuthId(attributes, provider, userNameAttributeName));
        else throw new IllegalArgumentException("유효하지 않은 provider 타입 입니다.");
    }

    //구글
    private static OAuthAttributes ofGoogle(Map<String, Object> attributes, String authId) {
        return OAuthAttributes.builder()
                .authId(authId)
                .name((String) attributes.get("name"))
                .email((String) attributes.get("email"))
                .build();
    }

    //카카오
    private static OAuthAttributes ofKakao(Map<String, Object> attributes, String authId) {
        Map<String, Object> account = (Map<String, Object>) attributes.get("kakao_account");
        Map<String, Object> profile = (Map<String, Object>) account.get("profile");

        return OAuthAttributes.builder()
                .authId(authId)
                .name((String) profile.get("nickname"))
                .email((String) account.get("email"))
                .build();
    }

    //네이버
    private static OAuthAttributes ofNaver(Map<String, Object> attributes, String authId) {
        Map<String, Object> response = (Map<String, Object>) attributes.get("response");

        return OAuthAttributes.builder()
                .authId(authId)
                .name((String) response.get("name"))
                .email((String) response.get("email"))
                .build();
    }

    public static String createAuthId(Map<String, Object> attributes, String provider, String userNameAttributeName) {
        // naver만 규칙이 다름
        if (provider.equals("naver")) {
            Map<String, Object> tmpResponse = (Map<String, Object>) attributes.get("response");
            return provider + "_" + tmpResponse.get("id");
        }
        else return provider + "_" + attributes.get(userNameAttributeName);
    }

    public User toEntity() {
        return User.builder()
                .authId(this.authId)
                .name(this.name)
                .email(this.email)
                .build();
    }
}
