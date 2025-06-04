package com.polio.gateway.security.converter;

import com.polio.gateway.infrastructure.keycloak.prop.KeycloakSecurityProperties;
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
        List<GrantedAuthority> authorities = new ArrayList<>();

        List<String> realmRoles = Optional.ofNullable(jwt.getClaimAsMap("realm_access"))
                .map(realm -> (List<String>) realm.get("roles"))
                .orElse(Collections.emptyList());
        realmRoles.forEach(role -> authorities.add(new SimpleGrantedAuthority("ROLE_" + role)));

        Map<String, Object> resourceAccess = jwt.getClaim("resource_access");
        if (resourceAccess != null && resourceAccess.containsKey(keycloakSecurityProperties.getClientId())) {
            Map<String, Object> clientRolesMap = (Map<String, Object>) resourceAccess.get(keycloakSecurityProperties.getClientId());
            List<String> clientRoles = (List<String>) clientRolesMap.get("roles");
            clientRoles.forEach(role -> authorities.add(new SimpleGrantedAuthority("ROLE_" + role)));
        }

        List<String> scopes = Optional.ofNullable(jwt.getClaimAsStringList("scope")).orElse(Collections.emptyList());
        scopes.forEach(scope -> authorities.add(new SimpleGrantedAuthority("SCOPE_" + scope)));

        return Flux.fromIterable(authorities);
    }

    public ReactiveJwtAuthenticationConverter buildConverter() {
        ReactiveJwtAuthenticationConverter converter = new ReactiveJwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(this); // 이제 타입이 일치
        return converter;
    }
}

