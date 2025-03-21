package com.linkmoa.auth.oauth;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

public class OAuth2UserPrincipal implements OAuth2User, UserDetails {

    private static final Set<GrantedAuthority> DEFAULT_AUTHORITIES =
            Collections.singleton(new SimpleGrantedAuthority("ROLE_USER"));

    @Getter
    private final Long id;

    private final String username;

    private final Map<String, Object> attributes;

    public OAuth2UserPrincipal(Long id, String username) {
        this.id = id;
        this.username = username;
        this.attributes = Collections.emptyMap();
    }

    public OAuth2UserPrincipal(Long id, String username, Map<String, Object> attributes) {
        this.id = id;
        this.username = username;
        this.attributes = Collections.unmodifiableMap(new LinkedHashMap<>(attributes));
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return DEFAULT_AUTHORITIES;
    }

    @Override
    public String getPassword() {
        // OAuth2 인증으로 비밀번호가 관리되지 않음
        return null;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public String getName() {
        return attributes.getOrDefault("name", username).toString();
    }
}
