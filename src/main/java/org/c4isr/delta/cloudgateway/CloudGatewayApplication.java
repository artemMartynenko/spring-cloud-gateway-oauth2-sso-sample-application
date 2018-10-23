package org.c4isr.delta.cloudgateway;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
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

    private static final Logger LOGGER = LoggerFactory.getLogger(CloudGatewayApplication.class);


    @Value("${spring.security.oauth2.client.provider.delta.jwk-set-uri}")
    private String keyUri;


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
                    .jwt();
        return http.build();
    }



    @Bean
    ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> userService(ReactiveJwtDecoder jwtDecoder){
        return new JwtReactiveOAuth2UserService(jwtDecoder);
    }

    @Bean
    ReactiveJwtDecoder jwtDecoder() throws IOException, InvalidKeyException {
       return WebClient.create().get().uri(URI.create(keyUri))
                .exchange()
                .flatMap(clientResponse -> clientResponse.bodyToMono(JwtPublicKey.class))
                .map(jwtPublicKey -> parsePublicKey(jwtPublicKey.getValue()))
                .map(NimbusReactiveJwtDecoder::new).block();
    }




    public static void main(String[] args) {
        SpringApplication.run(CloudGatewayApplication.class, args);

    }



    private RSAPublicKey parsePublicKey(String keyValue) {
        PemReader pemReader = new PemReader(new StringReader(keyValue));
        PemObject pem = null;
        try {
            pem = pemReader.readPemObject();
            return new RSAPublicKeyImpl(pem.getContent());
        } catch (IOException | InvalidKeyException e) {
            LOGGER.error("Unable to parse public key",e);
        }
        return null;
    }


}
