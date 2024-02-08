package com.ecomm.security.Service;

import com.ecomm.security.DAO.UniqueTokenRepo;
import com.ecomm.security.DAO.UserRepo;
import com.ecomm.security.Model.UniqueToken;
import com.ecomm.security.Model.UserEntity;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class UniqueTokenService {

    private UserRepo userRepo;
    private UniqueTokenRepo uniqueTokenRepo;

    public UniqueTokenService(UserRepo userRepo, UniqueTokenRepo uniqueTokenRepo) {
        this.userRepo = userRepo;
        this.uniqueTokenRepo = uniqueTokenRepo;
    }

    public void createUniqueToken(String email) {
          UniqueToken uniqueToken = UniqueToken.builder()
                .user(userRepo.findByEmail(email).get())
                .token(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusMillis(600000))//10
                .build();
        uniqueTokenRepo.save(uniqueToken);
    }


    public Optional<UniqueToken> findByToken(String token) {
        return uniqueTokenRepo.findByToken(token);
    }

    public String getUniqueToken(UserEntity user){
        return uniqueTokenRepo.findByUser(user).get().getToken();
    }
    public UniqueToken verifyExpiration(UniqueToken token) {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            uniqueTokenRepo.delete(token);
            throw new RuntimeException(token.getToken() + " Refresh token was expired. Please make a new signin request");
        }
        return token;
    }
}
