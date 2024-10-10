package com.ss.securitydb.service;

import com.ss.securitydb.entity.Users;
import com.ss.securitydb.repository.UserRepository;
import org.hibernate.Hibernate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.stream.Collectors;

/**
 * CustomUserDetailsService는 Spring Security에서 사용자 정보를 로드하기 위한 서비스 클래스입니다.
 * 이 클래스는 DB에서 사용자 정보를 가져오고, 그 정보를 기반으로 사용자 인증을 수행하는 역할을 합니다.
 */
@Service  // 이 클래스가 스프링의 서비스 레이어에서 사용될 것임을 명시합니다. 
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired  // 스프링 컨텍스트가 이 필드에 필요한 객체(UserRepository)를 자동으로 주입해줍니다.
    private UserRepository userRepository;

    /**
     * Spring Security가 제공하는 기본 메서드인 loadUserByUsername을 구현하여
     * DB에서 사용자를 조회하고, 인증에 필요한 UserDetails 객체를 반환합니다.
     * 
     * @param username 사용자가 로그인할 때 입력한 사용자명
     * @return UserDetails 인증에 필요한 사용자 정보
     * @throws UsernameNotFoundException 사용자를 찾을 수 없는 경우 발생하는 예외
     */
    @Override
    @Transactional // 이 메서드가 트랜잭션 내에서 실행됨을 나타냅니다. Lazy loading 문제를 방지하기 위해 필요합니다.
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 사용자를 DB에서 조회합니다.
        Users user = userRepository.findByUsername(username);

        // 만약 해당 사용자가 없으면, 예외를 던집니다.
        if (user == null) {
            throw new UsernameNotFoundException("사용자를 찾을 수 없습니다: " + username);
        }

        // Lazy loading이 필요한 roles 컬렉션을 강제로 초기화하여 
        // 이후 사용 시 세션이 닫혀있지 않도록 처리합니다.
        Hibernate.initialize(user.getRoles());

        // UserDetails 인터페이스를 구현하는 org.springframework.security.core.userdetails.User 객체를 반환합니다.
        // 이 객체는 Spring Security가 사용자 인증에 필요한 정보를 담고 있습니다.
        return new org.springframework.security.core.userdetails.User(
            user.getUsername(),  // 사용자의 이름 (username 필드)
            user.getPassword(),  // 암호화된 비밀번호 (password 필드)
            getAuthorities(user) // 사용자 권한 목록을 반환
        );
    }

    /**
     * 사용자의 역할(Role)을 Spring Security에서 사용하는 권한(GrantedAuthority)으로 변환하는 메서드입니다.
     * 
     * @param user 사용자 객체 (Users 엔티티)
     * @return 사용자 권한(GrantedAuthority)의 목록
     */
    private Collection<? extends GrantedAuthority> getAuthorities(Users user) {
        // 사용자의 roles 리스트를 스트림으로 변환한 후, 각각의 Role을 GrantedAuthority로 변환하여 수집합니다.
        // .map() 메서드는 각 Role을 SimpleGrantedAuthority로 변환합니다.
        // SimpleGrantedAuthority는 Spring Security에서 사용되는 권한 객체입니다.
        return user.getRoles().stream()
            .map(role -> new SimpleGrantedAuthority(role.getRole())) // 각각의 role 문자열을 권한 객체로 변환
            .collect(Collectors.toList());  // 변환된 권한 객체들을 리스트로 수집
    }
}
