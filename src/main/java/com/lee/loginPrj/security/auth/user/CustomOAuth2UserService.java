package com.lee.loginPrj.security.auth.user;

import com.lee.loginPrj.domain.user.User;
import com.lee.loginPrj.domain.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        //null 체크
        Assert.notNull(userRequest, "userRequest cannot be null");

        Map<String, Object> attributes = super.loadUser(userRequest).getAttributes();

        // Auth 서버 고유 id값
        String userNameAttributeName = userRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();

        //getRegistrationId (kakao, naver, google)
        String provider = userRequest.getClientRegistration().getRegistrationId();

        //create User entity
        OAuthAttributes attribute = OAuthAttributes.of(provider,userNameAttributeName,attributes);
        User user = attribute.toEntity();

        //saveOrUpdate
        userRepository.save(user);

        //return OAuth2User
        return CustomOAuth2User.create(user);
    }
}
