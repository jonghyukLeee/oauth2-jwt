package com.lee.loginPrj.domain.user;


import com.lee.loginPrj.security.auth.user.OAuthAttributes;
import lombok.*;

import javax.persistence.*;

@Getter
@Builder
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String authId;

    private String email;
    private String name;

    @Builder.Default
    @Enumerated(EnumType.STRING)
    private Role role = Role.USER;

    @Builder.Default
    boolean isMember = true;

    @Builder
    public User(OAuthAttributes attributes) {
        this.authId = attributes.getAuthId();
        this.email = attributes.getEmail();
        this.name = attributes.getName();
    }
}
