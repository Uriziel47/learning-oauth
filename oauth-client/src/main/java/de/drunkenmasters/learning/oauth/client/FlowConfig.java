package de.drunkenmasters.learning.oauth.client;

import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;

import java.net.URI;
import java.util.Optional;

public record FlowConfig(
        ClientID clientId,
        Optional<Secret> clientSecret,

        URI authenticationEndpoint,
        URI callbackEndpoint,
        URI tokenEndpoint
) {
}
