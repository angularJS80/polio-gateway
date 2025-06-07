package com.polio.gateway.security.authroization;

import com.polio.poliokeycloak.keycloak.client.dto.PermissionRule;
import com.polio.poliokeycloak.keycloak.dto.RoleRule;
import com.polio.poliokeycloak.keycloak.service.KeycloakPermissionService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class PermissionRuleAuthorizationManager {
    private final KeycloakPermissionService keycloakPermissionService;



    public AuthorizationDecision check(Supplier<Authentication> authentication, AuthorizationContext authorizationContext, String uri, PermissionRule permissionRule) {

        // 접근한 메소드
        authorizationContext.getExchange().getRequest().getMethod();


        boolean isValidUmaTicket =false;
        if (authentication.get() instanceof JwtAuthenticationToken jwtAuthenticationToken) {
            String tokenValue = jwtAuthenticationToken.getToken().getTokenValue();
             isValidUmaTicket = keycloakPermissionService.requestUmaTicket(tokenValue,
                    uri,authorizationContext.getExchange().getRequest().getMethod());

        }

        return  new AuthorizationDecision(isValidUmaTicket);
    }


}

