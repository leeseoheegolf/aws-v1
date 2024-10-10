package com.ss.securitydb.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.ss.securitydb.entity.Role;

public interface RoleRepository
	extends JpaRepository<Role, Long>{

}
