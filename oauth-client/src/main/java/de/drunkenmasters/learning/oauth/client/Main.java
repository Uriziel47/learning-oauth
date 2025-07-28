package de.drunkenmasters.learning.oauth.client;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import lombok.extern.slf4j.Slf4j;

import java.net.URI;
import java.text.ParseException;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

@Slf4j
public class Main {

    public static void main(String... args) throws Exception {
        var tokenFlowConfig = new FlowConfig(
                new ClientID("oauth-learning-client"),
                Optional.of(new Secret("8JFFji2h0Ml1IT3EpxOM3Ls2BaVyd6mq")),
                URI.create("http://localhost:8080/realms/oauth-learning/protocol/openid-connect/auth"),
                URI.create("http://localhost:3000/callback"),
                URI.create("http://localhost:8080/realms/oauth-learning/protocol/openid-connect/token")
        );

        Scope scope = new Scope(
                "openid",
                "basic",
                "profile",
                "microprofile-jwt"
        );

        var authResponse = authenticateWithPkce(tokenFlowConfig, scope);
        log.atInfo().log("Waiting a bit before refreshing...");
        Thread.sleep(TimeUnit.SECONDS.toMillis(3));
        refresh(tokenFlowConfig, scope, authResponse);
    }

    private static AuthenticationResponse authenticateWithPkce(FlowConfig tokeFlowConfig, Scope scope) throws Exception {
        var flow = TokenFlowWithPkce.of(tokeFlowConfig);
        var authResponseFuture = flow.authenticate(scope);
        var authResponse =  authResponseFuture.get(1, TimeUnit.MINUTES);

        logResponse(authResponse);

        return authResponse;
    }

    private static AuthenticationResponse refresh(
            FlowConfig tokeFlowConfig,
            Scope scope,
            AuthenticationResponse authResponse
    ) throws Exception {
        var flow = RefreshTokenFlow.of(tokeFlowConfig);
        var refreshResponse = flow.refresh(authResponse.getRefreshToken(), scope);

        logResponse(refreshResponse);

        return refreshResponse;
    }

    private static void logResponse(AuthenticationResponse authResponse) throws ParseException {
        log.atInfo().log("AccessToken: {}", authResponse.getAccessToken().getParsedString());
        log.atInfo().log("IdToken: {}", authResponse.getIdToken().getParsedString());
        log.atInfo().log("Name: {}", authResponse.getIdToken()
                .getJWTClaimsSet()
                .getClaim(ClaimNames.NAME.getName()));
        log.atInfo().log("RefreshToken: {}", authResponse.getRefreshToken().getParsedString());
    }

}
