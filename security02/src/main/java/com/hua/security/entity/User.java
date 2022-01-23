package com.hua.security.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class User implements UserDetails {

    private Long id;   // 主键

    private String username;  // 用户名

    private String password;   // 密码

    private String mobile;    // 手机号

    private String roles;    // 用户角色，多个角色之间用逗号隔开

    private boolean enabled;  // 用户是否可用

    private List<GrantedAuthority> authorities;  // 用户权限集合

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {  // 返回用户权限集合
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {  // 账户是否未过期
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {  // 账户是否未锁定
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {  // 密码是否未过期
        return true;
    }

    @Override
    public boolean isEnabled() {  // 账户是否可用
        return true;
    }

}
