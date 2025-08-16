package de.drunkenmasters.learning.oauth;

import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.Map;

@Getter
public class TestProperties {

    private Container container = Container.of();
    private Keycloak keycloak = Keycloak.of();


    public static final TestProperties of() {
        return new TestProperties();
    }


    @Getter
    @NoArgsConstructor(staticName = "of")
    public static class Container {
        private Map<String, String> containerLabels = Map.of(
                "junit.testing", "oauth-testing"
        );
        private boolean reuse = true;
    }

    @Getter
    @NoArgsConstructor(staticName = "of")
    public static class Keycloak {
        private String dockerImage = "quay.io/keycloak/keycloak:26.3.1";
        private String host = "keycloak.drunkenmasters.internal";
        private String certificate = "certs/star.drunkenmasters.internal.2.crt";
        private String certificateKey = "certs/star.drunkenmasters.internal.keyrsa";
    }


}
