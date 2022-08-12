package com.lee.loginPrj.domain.user;

import com.querydsl.jpa.impl.JPAQueryFactory;

import javax.persistence.EntityManager;
import java.util.Optional;

import static com.lee.loginPrj.domain.user.QUser.*;

public class UserRepositoryImpl implements UserRepositoryCustom{

    private final JPAQueryFactory queryFactory;

    public UserRepositoryImpl(EntityManager em)
    {
        queryFactory = new JPAQueryFactory(em);
    }

    @Override
    public Optional<Long> updateRefreshToken(Long id, String refreshToken) {
        return Optional.of(queryFactory
                .update(user)
                .set(user.refreshToken,refreshToken)
                .where(user.id.eq(id))
                .execute());
    }
}
