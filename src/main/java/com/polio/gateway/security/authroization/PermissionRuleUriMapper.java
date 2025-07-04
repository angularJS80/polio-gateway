package com.polio.gateway.security.authroization;
import com.polio.poliokeycloak.keycloak.service.KeycloakPermissionService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.security.web.server.util.matcher.OrServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
@RequiredArgsConstructor
public class PermissionRuleUriMapper {

    private final KeycloakPermissionService keycloakPermissionService;

    public void configureAuthorization(ServerHttpSecurity.AuthorizeExchangeSpec authz) {
        keycloakPermissionService.getUris()
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
        return monoAuthentication.map(authentication ->{
                boolean isValidUmaTicket =keycloakPermissionService.umaCheck(context, authentication, uri);
                return  new AuthorizationDecision(isValidUmaTicket);
            }
        );
    }

    public ServerWebExchangeMatcher getPublicSecurityMatcher() {
        List<ServerWebExchangeMatcher> matchers = keycloakPermissionService.hasNoPermissionsResources().stream()
                .flatMap(resource -> resource.getUris().stream())
                .map(uri -> (ServerWebExchangeMatcher) new PathPatternParserServerWebExchangeMatcher(uri))
                .toList();

        return new OrServerWebExchangeMatcher(matchers);
    }
}
