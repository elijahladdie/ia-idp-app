package com.ia.idp.repository;

import com.ia.idp.entity.AuthorizationCode;
import com.ia.idp.entity.OAuthClient;
import com.ia.idp.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface AuthorizationCodeRepository extends JpaRepository<AuthorizationCode, Long> {

    Optional<AuthorizationCode> findByCode(String code);

    Optional<AuthorizationCode> findByCodeAndUsedFalse(String code);

    @Query("SELECT ac FROM AuthorizationCode ac WHERE ac.code = :code AND ac.used = false AND ac.expiresAt > :now")
    Optional<AuthorizationCode> findValidCode(@Param("code") String code, @Param("now") LocalDateTime now);

    @Modifying
    @Query("DELETE FROM AuthorizationCode ac WHERE ac.expiresAt < :now")
    void deleteExpiredCodes(@Param("now") LocalDateTime now);

    @Modifying
    @Query("DELETE FROM AuthorizationCode ac WHERE ac.user = :user")
    void deleteByUser(@Param("user") User user);

    @Modifying
    @Query("DELETE FROM AuthorizationCode ac WHERE ac.client = :client")
    void deleteByClient(@Param("client") OAuthClient client);

    @Query("SELECT COUNT(ac) FROM AuthorizationCode ac WHERE ac.user = :user AND ac.expiresAt > :now")
    long countActiveCodesByUser(@Param("user") User user, @Param("now") LocalDateTime now);
}
