package com.backend.security.repo;

import com.backend.security.model.User;
import com.backend.security.model.UserRole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRoleRepository extends JpaRepository<UserRole, Long> {

    @Query("SELECT role FROM UserRole role WHERE role.name = 'USER'")
    UserRole getRoleUser();
}
