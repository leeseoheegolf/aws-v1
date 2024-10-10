package com.ss.securitydb.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.ss.securitydb.entity.Role;
import com.ss.securitydb.entity.Users;
import com.ss.securitydb.service.UserService;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Controller
public class SecurityController {
	
	@Autowired
	private UserService userService;
	
	
	@GetMapping("/security")
	public String securityMain() {
		return "security/index";
	}

	@GetMapping("/security/admin")
	public String adminPage() {
		return "security/admin";
	}

	@GetMapping("/security/user")
	public String userPage() {
		return "security/user";
	}

	@GetMapping("/login")
	public String loginPage() {
		return "security/login"; // 로그인 페이지로 이동
	}
	
	
	@GetMapping("/join")
	public String joinPage(Model model) {
		// 타임리프를 이용해서 object속성이 붙으면
		// 실제 뷰페이지를 보여주는 get요청에서는
		// User객체를 생성해서 model에 
		// 담아서 보내줘야된다. 
		model.addAttribute("user",new Users());
		
		return "security/join"; 
		
	}
	@PostMapping("/join")
	public String joinPro(Users user,
					@RequestParam("role")String role)
	{
		
		//사용자 등록 시 역할을 선택해서 데이터베이스
		// 에 저장하는 역할 메서드를 생성
		userService.joinUserWithRole(user,role);
		
		// 회원가입 후에 로그인 페이지로 이동!
		return "redirect:/login"; 		
	}
}
