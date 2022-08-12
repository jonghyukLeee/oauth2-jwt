package com.lee.loginPrj.domain.user;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum Role {
    ADMIN("관리자"),
    USER("사용자"),
    SELLER("판매자");

    private final String role;
}
