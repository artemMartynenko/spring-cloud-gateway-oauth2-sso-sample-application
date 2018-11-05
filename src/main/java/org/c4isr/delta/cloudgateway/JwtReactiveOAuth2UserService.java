package org.c4isr.delta.cloudgateway;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import reactor.core.publisher.Mono;

import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;

public class JwtReactiveOAuth2UserService implements ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final ReactiveJwtDecoder jwtDecoder;

    public JwtReactiveOAuth2UserService( ReactiveJwtDecoder jwtDecoder) {
        this.jwtDecoder = jwtDecoder;
    }

    @Override
    public Mono<OAuth2User> loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        return  jwtDecoder.decode(userRequest.getAccessToken()
                .getTokenValue())
                .map(jwt -> new JwtOAuth2User(toGrantedAuthorities(jwt.getClaims()),jwt.getClaims(),"user_name",jwt.getTokenValue()));
    }


    private Collection<? extends GrantedAuthority> toGrantedAuthorities(Map<String,Object> claims){
        Collection<String> stringAuthorities = (Collection<String>) claims.get("authorities");
        if(stringAuthorities != null ) {
            return stringAuthorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
        }else {
            return null;
        }
    }

}
