package org.c4isr.delta.cloudgateway.jwt;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import reactor.core.publisher.Mono;

public class JwtReactiveOAuth2UserService implements ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final ReactiveJwtDecoder jwtDecoder;
    private final Converter<Jwt, JwtOAuth2User> jwtToUserConverter = new JwtToOAuth2UserConverter();

    public JwtReactiveOAuth2UserService(ReactiveJwtDecoder jwtDecoder) {
        this.jwtDecoder = jwtDecoder;
    }

    @Override
    public Mono<OAuth2User> loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        return jwtDecoder.decode(userRequest.getAccessToken()
                .getTokenValue())
                .map(jwtToUserConverter::convert);
    }


}
