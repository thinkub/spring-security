package com.ming.user.repository;

import com.ming.user.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/**
 * @Author by mhlee(mhlee@saltlux.com) on 2020-08-19
 */
public interface UserRepository extends JpaRepository<UserEntity, Long> {
	Optional<UserEntity> findByUserId(String userId);
}
