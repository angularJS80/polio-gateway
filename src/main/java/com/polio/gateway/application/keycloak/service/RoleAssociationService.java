package com.polio.gateway.application.keycloak.service;

import com.polio.gateway.application.keycloak.dto.RoleRule;
import com.polio.gateway.infrastructure.keycloak.prop.client.KeycloakAdminClient;
import com.polio.gateway.infrastructure.keycloak.prop.dto.PermissionRule;
import com.polio.gateway.infrastructure.keycloak.prop.dto.PolicyWithRole;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class RoleAssociationService {
    private final KeycloakAdminClient keycloakAdminClient;
    public PermissionRule associateRole(PermissionRule permissionRule) {
        keycloakAdminClient.retrievePolicyPermissionId(permissionRule.getPermissionId()).forEach(policy -> {
            permissionRule.setPolicy(policy);

            keycloakAdminClient.findPolicyWithRoleByPolicyId(policy.getId())
                    .flatMap(PolicyWithRole::findRoles)
                    .stream()
                    .flatMap(Collection::stream)
                    .map(roleConfig -> keycloakAdminClient.findRoleById(roleConfig.getId())
                            .map(role -> RoleRule.of(roleConfig, role.getName())))
                    .flatMap(Optional::stream)
                    .forEach(permissionRule::addRoleRule);
        });

        return permissionRule;
    }
}
