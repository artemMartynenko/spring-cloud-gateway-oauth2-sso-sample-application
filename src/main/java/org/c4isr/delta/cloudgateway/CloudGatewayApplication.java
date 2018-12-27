package org.c4isr.delta.cloudgateway;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.c4isr.delta.cloudgateway.jwt.JwtOAuth2AuthenticationTokenConverter;
import org.c4isr.delta.cloudgateway.jwt.JwtPublicKey;
import org.c4isr.delta.cloudgateway.jwt.JwtReactiveOAuth2UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.reactive.function.client.WebClient;
import sun.security.rsa.RSAPublicKeyImpl;

import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.security.InvalidKeyException;
import java.security.interfaces.RSAPublicKey;

@SpringBootApplication
public class CloudGatewayApplication {


    @Bean
    SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http
                .authorizeExchange()
                  .anyExchange()
                    .authenticated()
                .and()
                  .oauth2Login()
                .and()
                  .oauth2ResourceServer()
                    .jwt().jwtAuthenticationConverter(new JwtOAuth2AuthenticationTokenConverter());
        return http.build();
    }




    public static void main(String[] args) {
        SpringApplication.run(CloudGatewayApplication.class, args);

    }


}
