package org.c4isr.delta.cloudgateway.jwt;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;

public class JwtToOAuth2UserConverter implements Converter<Jwt, JwtOAuth2User> {




    @Override
    public JwtOAuth2User convert(Jwt jwt) {
        return new JwtOAuth2User(toGrantedAuthorities(jwt.getClaims()), jwt.getClaims(), "user_name", jwt.getTokenValue());
    }



    private Collection<? extends GrantedAuthority> toGrantedAuthorities(Map<String, Object> claims) {
        Collection<String> stringAuthorities = (Collection<String>) claims.get("authorities");
        if (stringAuthorities != null) {
            return stringAuthorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
        } else {
            return null;
        }
    }
}
