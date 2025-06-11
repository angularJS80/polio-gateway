package com.polio.gateway.security.authroization;
import com.polio.poliokeycloak.keycloak.helper.KeycloakHelper;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpMethod;
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

    private final KeycloakHelper keycloakHelper;

    public void configureAuthorization(ServerHttpSecurity.AuthorizeExchangeSpec authz) {
        // 보호대상의 패턴들을
        keycloakHelper.hasPermissionsPatterns()
                        .forEach(patternUri->
                            // 인가 체크 대상에 체크기준과 함께 넣는다.
                            authz.pathMatchers(patternUri)
                                    .access(this::check)
                        );
    }

    public Mono<AuthorizationDecision> check(Mono<Authentication> monoAuthentication, AuthorizationContext context) {
        HttpMethod httpMethod = context.getExchange().getRequest().getMethod();
        String targetUri = context.getExchange().getRequest().getURI().getPath();
        return monoAuthentication.map(auth -> keycloakHelper.decide(httpMethod, auth, targetUri));
    }

    public ServerWebExchangeMatcher getPublicSecurityMatcher() {
        List<ServerWebExchangeMatcher> matchers = keycloakHelper.hasNoPermissionsPatterns()
                .stream()
                .map(patternUris -> (ServerWebExchangeMatcher) new PathPatternParserServerWebExchangeMatcher(patternUris))
                .toList();
        return new OrServerWebExchangeMatcher(matchers);
    }
}
