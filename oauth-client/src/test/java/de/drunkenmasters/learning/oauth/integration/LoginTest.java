package de.drunkenmasters.learning.oauth.integration;

import com.nimbusds.oauth2.sdk.Scope;
import de.drunkenmasters.learning.oauth.client.FlowConfig;
import de.drunkenmasters.learning.oauth.client.TokenFlowWithPkce;
import lombok.extern.slf4j.Slf4j;
import org.jsoup.Jsoup;
import org.junit.jupiter.api.Test;

import java.net.CookieManager;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
public class LoginTest {

    @Test
    void login() throws Exception {
        var tokenFlowConfig = FlowConfig.builder()
                .clientId("oauth-learning-client")
                .clientSecret("8JFFji2h0Ml1IT3EpxOM3Ls2BaVyd6mq")
                .authenticationEndpoint("https://keycloak.drunkenmasters.internal:8443/realms/oauth-testing/protocol/openid-connect/auth")
                .callbackEndpoint("http://localhost:3000/callback")
                .tokenEndpoint("https://keycloak.drunkenmasters.internal:8443/realms/oauth-testing/protocol/openid-connect/token")
                .build();

        Scope scope = new Scope(
                "openid",
                "basic",
                "profile",
                "microprofile-jwt"
        );

        var flow = TokenFlowWithPkce.of(tokenFlowConfig);
        var authResponseFuture = flow.authenticate(this::usernamePasswordLogin, scope);
        var authResponse = authResponseFuture.get(1, TimeUnit.MINUTES);
        System.out.println(authResponse.getAccessToken().getParsedString());
        assertThat(authResponse).isNotNull();
    }

    private void usernamePasswordLogin(URI loginUri) {
        System.out.println("Login: "  + loginUri);
        var cookieManager = new CookieManager();
        var httpClient = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL)
                .cookieHandler(cookieManager)
                .build();

        var httpRequest = HttpRequest.newBuilder()
                .uri(loginUri)
                .GET()
                .build();

        try {
            var response = httpClient.send(
                    httpRequest,
                    HttpResponse.BodyHandlers.ofString());
            var resCode = response.statusCode();
            var resHtml = response.body();

            var soup = Jsoup.parse(resHtml);
            var formAction = soup.getElementById("kc-form-login");

            var action = formAction.attribute("action").getValue();
            var formData = Map.of(
                    "username", "work",
                    "password", "x");
            var formBody = formData.entrySet().stream()
                    .map(e ->
                                    URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8)
                                    + "="
                                    + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8)
                    )
                    .collect(Collectors.joining("&"));
            var loginRequest = HttpRequest.newBuilder()
                    .uri(URI.create(action))
                    .headers("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(formBody))
                    .build();

            var loginResponse = httpClient.send(
                    loginRequest,
                    HttpResponse.BodyHandlers.ofString()
            );

            if (loginResponse.statusCode() == 302) {
                var callbackUri = loginResponse.headers().firstValue("Location").get();
                var callbackRequest = HttpRequest.newBuilder()
                        .uri(URI.create(callbackUri))
                        .GET()
                        .build();
                var callbackResponse =  httpClient.send(callbackRequest, HttpResponse.BodyHandlers.ofString());
                log.atInfo().log("Callback status: {}", callbackResponse.statusCode());
                cookieManager.getCookieStore().getCookies().stream()
                        .forEach(cookie -> log.atInfo().log(cookie.toString()));
            }
        } catch (Exception e) {
            log.atError().log("Error while logging in.", e);
        }

    }


}
