package com.polio.gateway.security;

import com.polio.gateway.security.authroization.PermissionRuleUriMapper;
import com.polio.gateway.security.converter.KeycloakReactiveJwtAuthenticationConverter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class GatewaySecurityConfig {

    private final KeycloakReactiveJwtAuthenticationConverter converter;

    private final PermissionRuleUriMapper permissionRuleUriMapper;

    @Bean
    @Order(0)
    public SecurityWebFilterChain publicWebFilterChain(ServerHttpSecurity http) {
        return http
                .securityMatcher(permissionRuleUriMapper.getPublicSecurityMatcher())
                .authorizeExchange(exchanges -> exchanges.anyExchange().permitAll())
                .build();
    }

    @Bean
    @Order(1)
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
                //.addFilterBefore(removeAuthHeaderFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .csrf(csrf -> csrf.disable())
                .authorizeExchange(authorizeExchangeSpec -> {
                            // 키클락에 정의한 정책에 해당하면 해당 기준에 따라 허용
                            permissionRuleUriMapper.configureAuthorization(authorizeExchangeSpec);

                            // 토큰만 있다면 나머지는 허용
                            authorizeExchangeSpec.anyExchange().authenticated();
                        }
                )
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(converter.buildConverter())));
        return http.build();
    }



}
