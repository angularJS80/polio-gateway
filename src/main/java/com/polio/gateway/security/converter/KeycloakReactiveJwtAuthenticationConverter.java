package com.polio.gateway.security.converter;

import com.polio.gateway.infrastructure.keycloak.prop.KeycloakSecurityProperties;
import com.polio.gateway.security.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

import java.util.*;

@Component
@RequiredArgsConstructor
public class KeycloakReactiveJwtAuthenticationConverter implements Converter<Jwt, Flux<GrantedAuthority>> {

    private final KeycloakSecurityProperties keycloakSecurityProperties;

    @Override
    public Flux<GrantedAuthority> convert(Jwt jwt) {
        return Flux.fromIterable(JwtUtil.convertAuthorities(jwt,keycloakSecurityProperties.getClientId()));
    }

    public ReactiveJwtAuthenticationConverter buildConverter() {
        ReactiveJwtAuthenticationConverter converter = new ReactiveJwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(this); // 이제 타입이 일치
        return converter;
    }
}

