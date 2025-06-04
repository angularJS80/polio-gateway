package com.polio.gateway.security.authroization;

import com.polio.gateway.application.keycloak.service.KeycloakPermissionService;
import com.polio.gateway.infrastructure.keycloak.prop.dto.PermissionRule;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.AbstractMap;

@Component
@RequiredArgsConstructor
public class PermissionRuleUriMapper {

    private final KeycloakPermissionService keycloakPermissionService;
    private final PermissionRuleAuthorizationManager authorizationManager;

    public void configureAuthorization(ServerHttpSecurity.AuthorizeExchangeSpec authz) {
        keycloakPermissionService.getPermissionRules().stream()
                .flatMap(permissionRule -> permissionRule.findResource().stream()
                        .flatMap(resource -> resource.getUris().stream()
                                .map(uri -> new AbstractMap.SimpleEntry<>(uri, permissionRule))))
                .forEach(entry -> {
                    String uri = entry.getKey();
                    PermissionRule permissionRule = entry.getValue();

                    authz.pathMatchers(uri)
                            .access((authentication, context) -> check(authentication, permissionRule));
                });
    }

    public Mono<AuthorizationDecision> check(Mono<Authentication> monoAuthentication, PermissionRule permissionRule) {
        return monoAuthentication.map(authentication ->
                authorizationManager.check(() -> authentication, permissionRule)
        );
    }
}
