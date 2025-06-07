package com.polio.gateway.security.authroization;

import com.polio.poliokeycloak.keycloak.client.dto.PermissionRule;
import com.polio.poliokeycloak.keycloak.service.KeycloakPermissionService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.AbstractMap;

@Component
@RequiredArgsConstructor
public class PermissionRuleUriMapper {

    private final KeycloakPermissionService keycloakPermissionService;
    private final PermissionRuleAuthorizationManager authorizationManager;

    public void configureAuthorization(ServerHttpSecurity.AuthorizeExchangeSpec authz) {
        keycloakPermissionService.getResources()
                        .stream()
                        .flatMap(resource -> resource.getUris().stream())
                                .forEach(uri->{
                                    if(keycloakPermissionService.isNoPermission(uri)){
                                        authz.pathMatchers(uri).permitAll();
                                    }else{
                                        authz.pathMatchers(uri)
                                                .access((authentication, context) -> check(authentication,context,uri));
                                    }
                                });

    }

    public Mono<AuthorizationDecision> check(Mono<Authentication> monoAuthentication, AuthorizationContext context, String uri) {
        return monoAuthentication.map(authentication ->
                authorizationManager.check(() -> authentication, context,uri)
        );
    }
}
