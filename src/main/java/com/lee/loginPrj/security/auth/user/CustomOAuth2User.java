package com.lee.loginPrj.security.auth.user;

import com.lee.loginPrj.domain.user.User;
import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.*;

@Getter
public class CustomOAuth2User implements OAuth2User, UserDetails {

    private Long id;
    private String authId;
    private Collection<? extends GrantedAuthority> authorities;
    private Map<String, Object> attributes;

    @Builder
    public CustomOAuth2User(Long id, String authId, Collection<? extends GrantedAuthority> authorities) {
        this.id = id;
        this.authId = authId;
        this.authorities = authorities;
    }

    public static CustomOAuth2User create(User user) {
        Collection<GrantedAuthority> collect = new ArrayList<>();
        collect.add(() -> user.getRole().toString());

        return CustomOAuth2User.builder()
                .id(user.getId())
                .authId(user.getAuthId())
                .authorities(collect)
                .build();
    }

    @Override
    public Map<String, Object> getAttributes() {
        return this.attributes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public String getUsername() {
        return null;
    }

    @Override
    public String getName() {
        return null;
    }

    @Override
    public boolean isAccountNonExpired() {
        return false;
    }

    @Override
    public boolean isAccountNonLocked() {
        return false;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return false;
    }

    @Override
    public boolean isEnabled() {
        return false;
    }

}
