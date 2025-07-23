package de.drunkenmasters.learning.oauth.client;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

public class BackLink {

    public static void main(String... args) throws Exception {
        var httpServer = HttpServer.create(new InetSocketAddress("localhost", 8090), 0);
        httpServer.createContext("/callback", Callback.of(httpServer));

        httpServer.start();
    }

    public static class Callback implements HttpHandler {
        private final HttpServer server;

        private Callback(HttpServer server) {
            this.server = server;
        }

        public static Callback of(HttpServer server) {
            return new Callback(server);
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            System.out.println("Received request with");
            exchange.getResponseHeaders().add("Content-Type", "text/plain");
            var body = "Hello World!".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        }
    }
}
