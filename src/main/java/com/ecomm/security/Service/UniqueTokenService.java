package com.ecomm.security.Service;

import com.ecomm.security.DAO.UniqueTokenRepo;
import com.ecomm.security.DAO.UserRepo;
import com.ecomm.security.Model.UniqueToken;
import com.ecomm.security.Model.UserEntity;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
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

    public UniqueToken findUniqueToken(String email) {
        var user = userRepo.findByEmail(email).get();
        if (getUniqueToken(user).isEmpty() || isUniqueTokenExpired(email)) {
            UniqueToken uniqueToken = UniqueToken.builder()
                    .user(userRepo.findByEmail(email).get())
                    .token(UUID.randomUUID().toString())
                    .expiryDate(Instant.now().plusMillis(600000))//10
                    .build();
            return uniqueTokenRepo.save(uniqueToken);
        }
        return uniqueTokenRepo.findByUser(user).get();
    }

    public Optional<UniqueToken> findByToken(String token) {
        return uniqueTokenRepo.findByToken(token);
    }

    public String getEmailFromToken(String token){
        return uniqueTokenRepo.findByToken(token).get().getUser().getEmail();
    }

    public String getUniqueToken(UserEntity user){
        if (uniqueTokenRepo.findByUser(user).isPresent())
        return uniqueTokenRepo.findByUser(user).get().getToken();
        else return "";
    }
    public UniqueToken verifyExpiration(UniqueToken token) {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            uniqueTokenRepo.delete(token);
            throw new AuthenticationCredentialsNotFoundException(
                    token.getToken() + " Refresh token was expired. Please make a new signin request");
        }
        return token;
    }

    public boolean isUniqueTokenExpired(String email){
        UserEntity user = userRepo.findByEmail(email).get();
        UniqueToken token = uniqueTokenRepo.findByUser(user).get();
        if (token.getExpiryDate().compareTo(Instant.now()) < 0){
            uniqueTokenRepo.delete(token);
            return true;
        }
        return false;
    }
}
