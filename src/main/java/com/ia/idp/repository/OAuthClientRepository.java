package com.ia.idp.repository;

import com.ia.idp.entity.OAuthClient;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface OAuthClientRepository extends JpaRepository<OAuthClient, String> {

    Optional<OAuthClient> findByClientIdAndIsActiveTrue(String clientId);

    @Query("SELECT c FROM OAuthClient c WHERE c.clientId = :clientId AND c.isActive = true")
    Optional<OAuthClient> findActiveClient(@Param("clientId") String clientId);

    boolean existsByClientId(String clientId);

    Optional<OAuthClient> findByClientId(String clientId);
}
