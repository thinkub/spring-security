package com.ming.config;

import com.ming.user.entity.UserEntity;
import com.ming.user.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;

/**
 * @Author by mhlee(mhlee@saltlux.com) on 2020-08-19
 */

@Component
public class JwtTokenProvider {
	private final UserDetailsService userDetailsService;
	private final UserRepository userRepository;

	@Value("${spring.jwt.secret}")
	private String secretKey;


	public JwtTokenProvider(@Lazy @Qualifier("userService") UserDetailsService userDetailsService,
	                        UserRepository userRepository) {
		this.userDetailsService = userDetailsService;
		this.userRepository = userRepository;
	}

	@PostConstruct
	protected void init() {
		secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
	}

	/**
	 * Jwt Token 생성
	 *
	 * @param userId
	 * @param roles
	 * @return
	 */
	public String createToken(String userId, List<String> roles) {
		Claims claims = Jwts.claims().setSubject(userId);
		claims.put("roles", roles);
		Date now = new Date();
		return Jwts.builder()
				.setClaims(claims)
				.setIssuedAt(now)
				.setExpiration(Date.from(
						LocalDateTime.now().plusDays(1).atZone(ZoneId.systemDefault()).toInstant()))
				.signWith(SignatureAlgorithm.HS256, secretKey)
				.compact();
	}

	/**
	 * 로그인 중복 체크를 위해 기존 로그인 사용자의 Token 을 Expired 된 것으로 변경하기 위한 method
	 *
	 * @param userId
	 * @param roles
	 * @return
	 */
	private String createExpiredToken(String userId, List<String> roles) {
		Claims claims = Jwts.claims().setSubject(userId);
		claims.put("roles", roles);
		Date now = new Date();
		return Jwts.builder()
				.setClaims(claims)
				.setIssuedAt(now)
				.setExpiration(Date.from(
						LocalDateTime.now().minusHours(1).atZone(ZoneId.systemDefault()).toInstant()))
				.signWith(SignatureAlgorithm.HS256, secretKey)
				.compact();
	}

	/**
	 * Jwt Token으로 인증정보 조회
	 *
	 * @param token
	 * @return
	 */
	Authentication getAuthentication(String token) {
		UserDetails userDetails = userDetailsService.loadUserByUsername(this.getUserId(token));
		return new UsernamePasswordAuthenticationToken(userDetails, "",
				userDetails.getAuthorities());
	}

	/**
	 * Jwt Token에서 회원정보 추출
	 *
	 * @param token
	 * @return
	 */
	private String getUserId(String token) {
		return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getSubject();
	}

	/**
	 * Request의 Header에서 token 파싱: X-AUTH_TOKEN: jwt Token
	 *
	 * @param req
	 * @return
	 */
	String resolveToken(HttpServletRequest req) {
		String token = req.getHeader("X-AUTH-TOKEN");
		if (token == null || "".equals(token)) {
			return null;
		}

		String userId = this.getUserId(token);
		Optional<UserEntity> userEntity = userRepository.findByUserId(userId);
		if (!userEntity.isPresent()) {
			return token;
		}

		UserEntity entity = userEntity.get();

		if (!entity.isSameToken(token)) {
			return this.createExpiredToken(entity.getUserId(), Collections
					.singletonList(entity.getUserRole().name()));
		}
		return token;
	}

	/**
	 * Jwt Token 유효성, 만료일자 확인
	 *
	 * @param jwtToken
	 * @return
	 */
	boolean validateToken(String jwtToken) {
		try {
			Jws<Claims> claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(jwtToken);
			return !claims.getBody().getExpiration().before(new Date());
		} catch (Exception e) {
			return false;
		}
	}
}
