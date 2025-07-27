package de.drunkenmasters.learning.oauth.client;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.Scope;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

public interface OauthFlow {
   CompletableFuture<JWT> authenticate(Consumer<URI> urlHandler, Scope scope) throws Exception;

   default CompletableFuture<JWT> authenticate(Scope scope) throws Exception {
       var logger = LoggerFactory.getLogger(OauthFlow.class);
       return authenticate(uri -> logger.info("Login via {}", uri.toString()), scope);
   }
}
