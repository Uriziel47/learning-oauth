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

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

public class TokenFlowWithPkce implements OauthFlow {


    private FlowConfig config;

    State state = new State("some-random-state");
    Scope scope = null;


    public TokenFlowWithPkce(FlowConfig config) {
        this.config = config;
    }

    public static final TokenFlowWithPkce of(FlowConfig config) {
        return new TokenFlowWithPkce(config);
    }

    public CompletableFuture<JWT> authenticate(Consumer<URI> urlHandler, Scope scope) throws Exception {
        this.scope = scope;
//        var codeVerifier = new CodeVerifier("ovoi--1PigftRok-mZc7nK2ii03jnko3pmJl9r97r54");
        var codeVerifier = new CodeVerifier();
        var requestUri = authenticateWithOpenId(codeVerifier);
        var jwtToken = startCallback(codeVerifier);
        System.out.println("Please login: " + requestUri);

        return jwtToken;
    }

    public URI authenticateWithOpenId(CodeVerifier code) throws Exception {
        var responseType = new ResponseType(ResponseType.Value.CODE);
//        responseType.add(new ResponseType.Value("id_token"));
//        responseType.add(ResponseType.Value.TOKEN);

        var request = new AuthorizationRequest.Builder(
                responseType, config.clientId()
        )
                .state(state)
                .scope(scope)
                .codeChallenge(code, CodeChallengeMethod.S256)
                .redirectionURI(config.callbackEndpoint())
                .endpointURI(config.authenticationEndpoint())
                .build();

        return request.toURI();
    }

    public CompletableFuture<JWT> startCallback(CodeVerifier code) throws Exception {
        var httpServer = HttpServer.create(new InetSocketAddress("localhost", 3000), 0);
        var jwtToken = new CompletableFuture<JWT>();
        Executors.newVirtualThreadPerTaskExecutor().execute(() -> {
            var callback = Callback.of(httpServer, this, jwtToken);
            callback.code(code);
            httpServer.createContext("/callback", callback);
            httpServer.start();
        });

        return jwtToken;
    }

    public JWT requestToken(CodeVerifier codeVerifier, AuthorizationCode code) throws Exception {
        var request = new TokenRequest(
                config.authTokenEndpoint(),
                config.clientId(),
                new AuthorizationCodeGrant(code, config.callbackEndpoint(), codeVerifier),
                scope
        );

        var response = request.toHTTPRequest().send();
        var jsonResponse = response.getBodyAsJSONObject();
        var tokenString = jsonResponse.getAsString("access_token");
        return JWTParser.parse(tokenString);
    }

    public static class Callback implements HttpHandler {
        private final HttpServer server;
        private final TokenFlowWithPkce flow;

        private CodeVerifier codeVerifier;
        private CompletableFuture<JWT> jwtToken;

        private Callback(HttpServer server, TokenFlowWithPkce flow, CompletableFuture<JWT> jwtToken) {
            this.server = server;
            this.flow = flow;
            this.jwtToken = jwtToken;
        }

        public static Callback of(HttpServer server, TokenFlowWithPkce flow, CompletableFuture<JWT> jwtToken) {
            return new Callback(server, flow, jwtToken);
        }

        public void code(CodeVerifier codeVerifier) {
            this.codeVerifier = codeVerifier;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            System.out.println("Received: " + exchange.getRequestURI());
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
                this.jwtToken.complete(jwtToken);
            } catch (Exception ex) {
                System.out.println(ex.getMessage());
                ex.printStackTrace();
                exchange.sendResponseHeaders(400, 0);
                this.jwtToken.completeExceptionally(ex);
            } finally {
                exchange.getResponseBody().close();
            }
        }
    }
}
