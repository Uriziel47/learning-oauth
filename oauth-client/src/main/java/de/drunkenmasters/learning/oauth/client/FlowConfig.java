package de.drunkenmasters.learning.oauth.client;

import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import lombok.Builder;

import java.net.URI;
import java.util.Optional;

@Builder
public record FlowConfig(
        ClientID clientId,
        Optional<Secret> clientSecret,

        URI authenticationEndpoint,
        URI callbackEndpoint,
        URI tokenEndpoint
) {

    public static class FlowConfigBuilder {

        public FlowConfigBuilder clientId(String clientId) {
            this.clientId = new ClientID(clientId);
            return this;
        }

        public FlowConfigBuilder clientSecret(Secret clientSecret) {
            this.clientSecret = Optional.of(clientSecret);
            return this;
        }

        public FlowConfigBuilder clientSecret(String clientSecret) {
            this.clientSecret = Optional.of(new Secret(clientSecret));
            return this;
        }

        public FlowConfigBuilder noClientSecret() {
            this.clientSecret = Optional.empty();
            return this;
        }

        public FlowConfigBuilder authenticationEndpoint(String authenticationEndpoint) {
            this.authenticationEndpoint = URI.create(authenticationEndpoint);
            return this;
        }

        public FlowConfigBuilder callbackEndpoint(String callbackEndpoint) {
            this.callbackEndpoint = URI.create(callbackEndpoint);
            return this;
        }

        public FlowConfigBuilder tokenEndpoint(String tokenEndpoint) {
            this.tokenEndpoint = URI.create(tokenEndpoint);
            return this;
        }
    }
}
