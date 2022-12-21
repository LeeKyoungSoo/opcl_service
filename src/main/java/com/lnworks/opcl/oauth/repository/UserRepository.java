package com.lnworks.opcl.oauth.repository;

import com.lnworks.opcl.oauth.vo.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    User findById (String username);
}

