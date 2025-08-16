package de.drunkenmasters.learning.oauth.integration.findouts;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.idm.RealmRepresentation;

import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
public class KeycloakContainerTest {
    private static final KeycloakContainer KEYCLOAK_CONTAINER =
            new KeycloakContainer("quay.io/keycloak/keycloak:26.3.1")
                    .withExtraHost("keycloak.drunkenmasters.internal", "127.0.0.1")
                    .useTls(
                            "certs/star.drunkenmasters.internal.2.crt",
                            "certs/star.drunkenmasters.internal.keyrsa"
                    )
//                    .withReuse(true)
//                    .withRealmImportFiles()
;
    @BeforeAll
    public static void setup() {
        KEYCLOAK_CONTAINER.start();
        log.atInfo().log("Keycloak: ");
        log.atInfo().log(KEYCLOAK_CONTAINER.getContainerIpAddress());
        log.atInfo().log(KEYCLOAK_CONTAINER.getContainerId());
        log.atInfo().log(KEYCLOAK_CONTAINER.getHost());
    }

    @AfterAll
    public static void teardown() {
        KEYCLOAK_CONTAINER.stop();
//        var adminClient = KEYCLOAK_CONTAINER.getKeycloakAdminClient();
    }

    @Test
    void containerIsStarted() {
        assertThat(KEYCLOAK_CONTAINER.isRunning())
                .isTrue();
    }
}
