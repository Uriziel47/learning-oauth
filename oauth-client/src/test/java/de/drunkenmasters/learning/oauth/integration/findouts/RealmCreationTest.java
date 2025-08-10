package de.drunkenmasters.learning.oauth.integration.findouts;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
public class RealmCreationTest {

    @Container
    KeycloakContainer keycloakContainer = new KeycloakContainer()
//            .withReuse(true)
            .withAdminUsername("admin")
            .withAdminPassword("adminx");


    @Test
    public void testRealmCreation() {
        keycloakContainer.start();
        System.out.println(keycloakContainer.getHost());
        System.out.println(keycloakContainer.getContainerName());
        System.out.println(keycloakContainer.isRunning());
    }
}
