package de.drunkenmasters.learning.oauth.client;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

public class KeycloakOauthFlow {


    ClientID clientId = new ClientID("oauth-learning-client");
    Secret clientSecret = new Secret("8JFFji2h0Ml1IT3EpxOM3Ls2BaVyd6mq");

    URI authenticationEndpoint = URI.create("http://localhost:8080/realms/oauth-learning/protocol/openid-connect/auth");
    URI callbackEndpoint = URI.create("http://localhost:3000/callback");
    URI tokenEndpoint = URI.create("http://localhost:8080/realms/oauth-learning/protocol/openid-connect/token");

    State state = new State("some-random-state");

    Scope scope = new Scope(
            "openid",
            "basic",
            "profile",
            "microprofile-jwt"
    );

    public static void main(final String[] args) throws Exception {
        var flow = new KeycloakOauthFlow();
        var codeVerifier = new CodeVerifier("ovoi--1PigftRok-mZc7nK2ii03jnko3pmJl9r97r54");
//        var codeVerifier = new CodeVerifier();
        var requestUri = flow.authenticateWithOpenId(codeVerifier);
        flow.startCallback(codeVerifier);
        System.out.println("Please login: " + requestUri);
    }

    public URI authenticateWithOpenId(CodeVerifier code) throws Exception {
        var responseType = new ResponseType(ResponseType.Value.CODE);
//        responseType.add(new ResponseType.Value("id_token"));
//        responseType.add(ResponseType.Value.TOKEN);

        var request = new AuthorizationRequest.Builder(
                responseType, clientId
        )
                .state(state)
                .scope(scope)
                .codeChallenge(code, CodeChallengeMethod.S256)
                .redirectionURI(callbackEndpoint)
                .endpointURI(authenticationEndpoint)
                .build();

        return request.toURI();
    }

    public void startCallback(CodeVerifier code) throws Exception {
        var httpServer = HttpServer.create(new InetSocketAddress("localhost", 3000), 0);
        var callback = Callback.of(httpServer, this);
        callback.code(code);
        httpServer.createContext("/callback", callback);
        httpServer.start();
    }

    public JWT requestToken(CodeVerifier codeVerifier, AuthorizationCode code) throws Exception {
        var request = new TokenRequest(
               tokenEndpoint,
                clientId,
                new AuthorizationCodeGrant(code, callbackEndpoint, codeVerifier),
                scope
        );

        var response = request.toHTTPRequest().send();
        var jsonResponse = response.getBodyAsJSONObject();
        var tokenString = jsonResponse.getAsString("access_token");
        return JWTParser.parse(tokenString);
    }

    public static class Callback implements HttpHandler {
        private final HttpServer server;
        private final KeycloakOauthFlow flow;

        private CodeVerifier codeVerifier;

        private Callback(HttpServer server, KeycloakOauthFlow flow) {
            this.server = server;
            this.flow = flow;
        }

        public static Callback of(HttpServer server,  KeycloakOauthFlow flow) {
            return new Callback(server, flow);
        }

        public void code(CodeVerifier codeVerifier) {
            this.codeVerifier = codeVerifier;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            System.out.println("Received: " +  exchange.getRequestURI());
            try {
                var response = AuthorizationResponse.parse(exchange.getRequestURI());
                exchange.sendResponseHeaders(200, 0);
                exchange.getResponseBody().close();

                System.out.println("State: " + response.getState());
                System.out.println("Success: " + response.indicatesSuccess());

                var successResponse = response.toSuccessResponse();
                var code = successResponse.getAuthorizationCode();
                System.out.println("Code: " + code.getValue());
                System.out.println("CodeVerifier: " + codeVerifier.getValue());

                var jwtToken = flow.requestToken(codeVerifier, code);
                System.out.println("JWT: " + jwtToken.getParsedString());
                System.out.println("Name: " + jwtToken.getJWTClaimsSet().getClaim("name"));
            } catch (Exception ex) {
                System.out.println(ex.getMessage());
                ex.printStackTrace();
                exchange.sendResponseHeaders(400, 0);
            } finally {
                exchange.getResponseBody().close();
            }
        }
    }
}
