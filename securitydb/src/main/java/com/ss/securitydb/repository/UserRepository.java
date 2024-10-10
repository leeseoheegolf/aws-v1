package com.ss.securitydb.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.ss.securitydb.entity.Users;

public interface UserRepository
			extends JpaRepository<Users, Long>{

	Users findByUsername(String name);

	
}
