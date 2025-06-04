package com.polio.gateway.application.keycloak.service;

import com.polio.gateway.infrastructure.keycloak.prop.client.KeycloakAdminClient;
import com.polio.gateway.infrastructure.keycloak.prop.dto.PermissionRule;
import com.polio.gateway.infrastructure.keycloak.prop.dto._IdentityInfo;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class ResourceAssociationService {
    private final KeycloakAdminClient keycloakAdminClient;
    public PermissionRule associateResource(PermissionRule permissionRule) {
        keycloakAdminClient.retrieveResourceIdentityPermission(permissionRule.getPermissionId())
                .stream()
                .map(_IdentityInfo::get_id)
                .map(keycloakAdminClient::findResourceById)
                .flatMap(Optional::stream)
                .findFirst()
                .ifPresent(permissionRule::setResource);

        return permissionRule;
    }
}
