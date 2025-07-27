package de.drunkenmasters.learning.oauth.client;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

public class TokenFlowWithPkce implements OauthFlow {
    private final FlowConfig config;

    public TokenFlowWithPkce(FlowConfig config) {
        this.config = config;
    }

    public static final TokenFlowWithPkce of(FlowConfig config) {
        return new TokenFlowWithPkce(config);
    }

    public CompletableFuture<JWT> authenticate(Consumer<URI> urlHandler, Scope scope) throws Exception {
        var codeVerifier = new CodeVerifier();
        var state = new State("some random state");

        var jwtToken = startCallback(codeVerifier, scope);
        var loginUri = buildRequestUri(codeVerifier, scope, state);
        urlHandler.accept(loginUri);

        return jwtToken;
    }

    public URI buildRequestUri(CodeVerifier code, Scope scope, State state) {
        var responseType = new ResponseType(ResponseType.Value.CODE);

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

    public CompletableFuture<JWT> startCallback(CodeVerifier code, Scope scope) throws Exception {
        var httpServer = HttpServer.create(new InetSocketAddress("localhost", 3000), 0);
        var jwtToken = new CompletableFuture<JWT>();
        Executors.newVirtualThreadPerTaskExecutor().execute(() -> {
            var callback = Callback.of(httpServer, config, code, scope, jwtToken);
            httpServer.createContext("/callback", callback);
            httpServer.start();
        });

        return jwtToken;
    }

    @Slf4j
    @AllArgsConstructor(staticName = "of")
    public static class Callback implements HttpHandler {
        private final HttpServer server;
        private final FlowConfig config;

        private final CodeVerifier codeVerifier;
        private final Scope scope;
        private final CompletableFuture<JWT> jwtToken;

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            log.debug("Received: {}", exchange.getRequestURI());
            try {
                var response = AuthorizationResponse.parse(exchange.getRequestURI());
                exchange.sendResponseHeaders(200, 0);
                exchange.getResponseBody().close();

                log.debug("State: {}", response.getState());
                log.debug("Success: {}", response.indicatesSuccess());

                var successResponse = response.toSuccessResponse();
                var code = successResponse.getAuthorizationCode();
                log.debug("Code: {}", code.getValue());
                log.debug("CodeVerifier: {}", codeVerifier.getValue());

                var jwtToken = requestToken(codeVerifier, code, scope);
                log.debug("JWT: {}", jwtToken.getParsedString());
                log.debug("Name: {}", jwtToken.getJWTClaimsSet().getClaim(ClaimNames.NAME.getName()));
                this.jwtToken.complete(jwtToken);
            } catch (Exception ex) {
                log.error("Error during authentication", ex);
                exchange.sendResponseHeaders(400, 0);
                this.jwtToken.completeExceptionally(ex);
            } finally {
                exchange.getResponseBody().close();
                server.stop(0);
            }
        }

        public JWT requestToken(CodeVerifier codeVerifier, AuthorizationCode code, Scope scope) throws Exception {
            var request = new TokenRequest(
                    config.authTokenEndpoint(),
                    config.clientId(),
                    new AuthorizationCodeGrant(code, config.callbackEndpoint(), codeVerifier),
                    scope
            );

            var response = request.toHTTPRequest().send();
            var jsonResponse = response.getBodyAsJSONObject();
            log.debug("Response: {}", jsonResponse);
            var tokenString = jsonResponse.getAsString(ClaimNames.ACCESS_TOKEN.getName());
            return JWTParser.parse(tokenString);
        }

    }
}
