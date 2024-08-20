package com.alibou.security.repositories;

import java.util.Optional;

import com.alibou.security.model.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Integer> {

  Optional<User> findByEmail(String email);

}
