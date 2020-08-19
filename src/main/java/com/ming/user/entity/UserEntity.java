package com.ming.user.entity;

import com.ming.user.model.UserRole;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.StringUtils;

import javax.persistence.*;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Collections;

/**
 * @Author by mhlee(mhlee@saltlux.com) on 2020-08-19
 */

@Entity
@Getter
@Table(name = "user")
@NoArgsConstructor
@EntityListeners(AuditingEntityListener.class)
public class UserEntity implements UserDetails {
	@Id
	@Column(name = "user_seq")
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long userSeq;

	@Column(name = "user_id", unique = true, nullable = false, length = 30)
	private String userId;

	@Setter
	@Column(name = "password", nullable = false, length = 300)
	private String password;

	@Column(name = "user_name", length = 30)
	private String userName;

	@Column(name = "user_role", nullable = false, length = 10)
	@Enumerated(EnumType.STRING)
	private UserRole userRole;

	@Column(name = "token")
	private String token;

	@CreatedDate
	@Column(name = "register_datetime", nullable = false)
	private LocalDateTime registerDatetime;

	@Column(name = "register_user_seq", nullable = false)
	private Long registerUserSeq;

	@LastModifiedDate
	@Column(name = "modify_datetime")
	private LocalDateTime modifyDatetime;

	@Column(name = "modify_user_seq")
	private Long modifyUserSeq;

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return Collections.singletonList(new SimpleGrantedAuthority(this.userRole.name()));
	}

	@Override
	public String getUsername() {
		return this.userName;
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}

	public boolean isSameToken(String token) {
		if (StringUtils.isEmpty(token)) {
			return false;
		}
		return token.equals(this.token);
	}

}
