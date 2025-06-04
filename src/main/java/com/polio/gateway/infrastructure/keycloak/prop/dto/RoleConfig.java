package com.polio.gateway.infrastructure.keycloak.prop.dto;

import lombok.Data;

@Data
public class RoleConfig {
    private String id;
    private boolean required;
}
