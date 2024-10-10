package com.ss.securitydb.service;

import com.ss.securitydb.entity.Role;
import com.ss.securitydb.entity.Users;
import com.ss.securitydb.repository.RoleRepository;
import com.ss.securitydb.repository.UserRepository;

import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class UserService {

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private RoleRepository roleRepository;

	public void joinUserWithRole(Users user, String role) {

		System.out.println("Users :" + user);
		System.out.println("role:" + role);
		user.setPassword(passwordEncoder.encode(user.getPassword()));
		Users user1 = userRepository.save(user);

		System.out.println("저장된 user:" + user1);

		Role userRole = new Role();
		userRole.setUsername(user.getUsername());

		if (role.equals("ADMIN")) {
			userRole.setRole("ROLE_ADMIN");
		} else {
			userRole.setRole("ROLE_USER");
		}

		roleRepository.save(userRole);
	}
}
