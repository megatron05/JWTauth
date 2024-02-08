package com.ecomm.security.DAO;

import com.ecomm.security.Model.UniqueToken;
import com.ecomm.security.Model.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;


public interface UniqueTokenRepo extends JpaRepository<UniqueToken, Integer> {
    Optional<UniqueToken> findByToken(String token);
    Optional<UniqueToken> findByUser(UserEntity user);
}
