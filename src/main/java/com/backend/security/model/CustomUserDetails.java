package com.backend.security.model;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Map;

@Getter
@Setter
public class CustomUserDetails implements UserDetails {

    private final Long id;
    private final String username;
    private final String password;
    Collection<? extends GrantedAuthority> authorities;
    @Setter
    private Map<String, Object> attributes;


    public CustomUserDetails(User user) {
        this.id = user.getId();
        this.username = user.getUsername();
        this.password = user.getPassword();
        this.authorities = user.getAuthorities();
    }

    public static CustomUserDetails create(User user) {
        return new CustomUserDetails(user);
    }

    public static CustomUserDetails create(User user, Map<String, Object> attributes) {
        CustomUserDetails userPrincipal = CustomUserDetails.create(user);
        userPrincipal.setAttributes(attributes);
        return userPrincipal;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
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
}
