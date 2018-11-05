package org.c4isr.delta.cloudgateway.filter;

import org.c4isr.delta.cloudgateway.jwt.JwtOAuth2User;
import org.slf4j.*;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Component;


@Component("Oauth2SSOGatewayFilterFactory")
public class PreOauth2SSOGatewayFilter extends AbstractGatewayFilterFactory<PreOauth2SSOGatewayFilter.Config> {


    private final Logger LOGGER = LoggerFactory.getLogger(PreOauth2SSOGatewayFilter.class);


    public PreOauth2SSOGatewayFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange,chain) -> ReactiveSecurityContextHolder.getContext()
                  .map(securityContext -> securityContext.getAuthentication())
                  .map(authentication -> (OAuth2AuthenticationToken) authentication)
                  .map(oAuth2Authentication -> oAuth2Authentication.getPrincipal())
                  .map(o -> (JwtOAuth2User) o)
                  .map(jwtOAuth2User -> jwtOAuth2User.getJwtTokenValue())
                  .flatMap(bearerToken -> {
          ServerHttpRequest.Builder builder = exchange.getRequest().mutate();
          builder.header(HttpHeaders.AUTHORIZATION,"Bearer "+bearerToken);
          ServerHttpRequest request = builder.build();
          return chain.filter(exchange.mutate().request(request).build());
      });
    }




    public static class Config{

    }

}
