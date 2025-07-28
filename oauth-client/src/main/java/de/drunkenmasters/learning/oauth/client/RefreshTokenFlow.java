package de.drunkenmasters.learning.oauth.client;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@AllArgsConstructor(staticName = "of")
public class RefreshTokenFlow {

    private FlowConfig config;

    public AuthenticationResponse refresh(JWT refreshToken, Scope scope) throws Exception {
        var token = new RefreshToken(refreshToken.getParsedString());
        var refreshTokenGrant = new RefreshTokenGrant(token);
        var request = new TokenRequest
                .Builder(
                config.tokenEndpoint(),
                config.clientId(),
                refreshTokenGrant)
                .scope(scope)
                .build();

        var response = request.toHTTPRequest().send();
        var jsonResponse = response.getBodyAsJSONObject();
        log.atDebug().log("Response: {}", jsonResponse);

        return AuthenticationResponseMapper.of()
                .from(jsonResponse);
    }
}
