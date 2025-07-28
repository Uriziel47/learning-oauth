package de.drunkenmasters.learning.oauth.client;

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
import java.io.PrintWriter;
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

    public CompletableFuture<AuthenticationResponse> authenticate(Consumer<URI> urlHandler, Scope scope) throws Exception {
        var codeVerifier = new CodeVerifier();
        var state = new State("some random state");

        var authResponse = startCallback(codeVerifier, scope);
        var loginUri = buildRequestUri(codeVerifier, scope, state);
        urlHandler.accept(loginUri);

        return authResponse;
    }

    public URI buildRequestUri(CodeVerifier code, Scope scope, State state) {
        var responseType = new ResponseType(ResponseType.Value.CODE);

        var request = new AuthorizationRequest
                .Builder(responseType, config.clientId())
                .state(state)
                .scope(scope)
                .codeChallenge(code, CodeChallengeMethod.S256)
                .redirectionURI(config.callbackEndpoint())
                .endpointURI(config.authenticationEndpoint())
                .build();

        return request.toURI();
    }

    public CompletableFuture<AuthenticationResponse> startCallback(CodeVerifier code, Scope scope) throws Exception {
        var endpoint = config.callbackEndpoint();
        var httpServer = HttpServer.create(
                new InetSocketAddress(
                        endpoint.getHost(),
                        endpoint.getPort()),
                0);
        var authResponse = new CompletableFuture<AuthenticationResponse>();
        Executors.newVirtualThreadPerTaskExecutor().execute(() -> {
            var callback = Callback.of(
                    httpServer,
                    config,
                    code,
                    scope,
                    authResponse
            );
            httpServer.createContext(endpoint.getPath(), callback);
            httpServer.start();
        });

        return authResponse;
    }

    @Slf4j
    @AllArgsConstructor(staticName = "of")
    public static class Callback implements HttpHandler {
        private final HttpServer server;
        private final FlowConfig config;

        private final CodeVerifier codeVerifier;
        private final Scope scope;
        private final CompletableFuture<AuthenticationResponse> responseFuture;

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            log.debug("Received: {}", exchange.getRequestURI());
            try {
                var response = AuthorizationResponse.parse(exchange.getRequestURI());
                exchange.sendResponseHeaders(200, 0);
                writeResponse(exchange);
                exchange.getResponseBody().close();

                log.debug("State: {}", response.getState());
                log.debug("Success: {}", response.indicatesSuccess());

                var successResponse = response.toSuccessResponse();
                var code = successResponse.getAuthorizationCode();
                log.debug("Code: {}", code.getValue());
                log.debug("CodeVerifier: {}", codeVerifier.getValue());

                var authResponse = requestToken(codeVerifier, code, scope);
                log.debug("JWT: {}", authResponse.getAccessToken()
                        .getParsedString());
                log.debug("Name: {}", authResponse.getIdToken()
                        .getJWTClaimsSet()
                        .getClaim(ClaimNames.NAME.getName()));

                responseFuture.complete(authResponse);
            } catch (Exception ex) {
                log.error("Error during authentication", ex);
                exchange.sendResponseHeaders(400, 0);
                responseFuture.completeExceptionally(ex);
            } finally {
                exchange.getResponseBody().close();
            }
            server.stop(0);
        }

        public AuthenticationResponse requestToken(
                CodeVerifier codeVerifier,
                AuthorizationCode code,
                Scope scope
        ) throws Exception {
            var request = new TokenRequest(
                    config.tokenEndpoint(),
                    config.clientId(),
                    new AuthorizationCodeGrant(code, config.callbackEndpoint(), codeVerifier),
                    scope
            );

            var response = request.toHTTPRequest().send();
            var jsonResponse = response.getBodyAsJSONObject();
            log.debug("Response: {}", jsonResponse);
            return AuthenticationResponseMapper.of()
                    .from(jsonResponse);
        }

        private void writeResponse(HttpExchange exchange) throws IOException {
            try (PrintWriter writer = new PrintWriter(exchange.getResponseBody())) {
                // language=html
                writer.print("""
                        <html lang="utf-8">
                            <head>
                                <title>redirect</title>
                                <script>
                                window.onload = function() {
                                    window.close();
                                };
                                </script>
                            </head>
                            <body>
                                <p>This window should close.</p>
                            </body>
                        </html>""");
                writer.flush();
            }
        }
    }
}
