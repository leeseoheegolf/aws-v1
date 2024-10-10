package com.ss.securitydb.entity;

import java.io.Serializable;
import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.OneToMany;

import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class Users implements Serializable {

	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;
	
	// unique 사용자 이름은 중복허용X
	@Column(nullable = false
			 ,unique = true)	
	private String username;
	
	@Column(nullable = false)
	private String password;
	private boolean enabled;   //계정활성화 1 활성화,0비활성화
	
	@OneToMany(cascade = CascadeType.ALL,fetch = FetchType.EAGER)
    @JoinColumn(name = "username", referencedColumnName = "username") // username을 연결
	private List<Role> roles;
		
}
