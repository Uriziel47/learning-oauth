package de.drunkenmasters.learning.oauth.findouts;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import java.net.URI;

@Slf4j
public class SmallFindoutsTest {

    @Test
    void uriExtraction() {
        var uriString = "http://localhost:3000/callback";
        var uri = URI.create(uriString);

        log.atInfo().log("uri: {}", uri.toASCIIString());
        log.atInfo().log("host: {}", uri.getHost());
        log.atInfo().log("port: {}", uri.getPort());
        log.atInfo().log("path: {}", uri.getPath());

    }
}
