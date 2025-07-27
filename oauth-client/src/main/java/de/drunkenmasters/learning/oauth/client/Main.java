package de.drunkenmasters.learning.oauth.client;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import lombok.extern.slf4j.Slf4j;

import java.net.URI;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

@Slf4j
public class Main {

    public static void main(String... args) throws Exception {
        var tokeFlowConfig = new FlowConfig(
                new ClientID("oauth-learning-client"),
                Optional.of(new Secret("8JFFji2h0Ml1IT3EpxOM3Ls2BaVyd6mq")),
                URI.create("http://localhost:8080/realms/oauth-learning/protocol/openid-connect/auth"),
                URI.create("http://localhost:3000/callback"),
                URI.create("http://localhost:8080/realms/oauth-learning/protocol/openid-connect/token"),
                Optional.empty()
        );

        Scope scope = new Scope(
                "openid",
                "basic",
                "profile",
                "microprofile-jwt"
        );

        var flow = TokenFlowWithPkce.of(tokeFlowConfig);
        var jwtFuture = flow.authenticate(scope);
        var jwt =  jwtFuture.get(1, TimeUnit.MINUTES);
        log.info("JWT: {}", jwt.getParsedString());
        log.info("Name: {}", jwt.getJWTClaimsSet().getStringClaim(ClaimNames.NAME.getName()));
    }
}
