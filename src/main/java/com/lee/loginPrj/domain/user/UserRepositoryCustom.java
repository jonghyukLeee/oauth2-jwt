package com.lee.loginPrj.domain.user;

import java.util.Optional;

public interface UserRepositoryCustom {
    Optional<Long> updateRefreshToken(Long id, String refreshToken);
}
