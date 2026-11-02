package com.oviva.ehealthid.relyingparty;

import static io.restassured.RestAssured.given;

import com.oviva.ehealthid.relyingparty.test.EmbeddedRelyingParty;
import io.restassured.http.ContentType;
import org.junit.jupiter.api.Test;

// The native app posts the relayed callback to /auth/relay (see the iOS HealthID return relay).
// These run the whole server, so they also cover routing and form parsing.
class MainRelayTest {

  // Shape the app sends: base64url S256 verifier, 43 characters.
  private static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

  @Test
  void relayEnabled_routesFormPostAndRejectsUnknownState() throws Exception {
    try (var rp =
        new EmbeddedRelyingParty("app_relay_uri=diga.staging.smokefreeapp://healthid_return")) {
      var relayUri = rp.start().resolve("/auth/relay");

      given()
          .contentType(ContentType.URLENC)
          .formParam("state", "unknown-state")
          .formParam("code", "some-code")
          .formParam("verifier", VERIFIER)
          .when()
          .post(relayUri)
          .then()
          .statusCode(400);

      given().when().get(relayUri).then().statusCode(405);
    }
  }

  @Test
  void relayDisabled_isNotFound() throws Exception {
    try (var rp = new EmbeddedRelyingParty()) {
      var relayUri = rp.start().resolve("/auth/relay");

      given()
          .contentType(ContentType.URLENC)
          .formParam("state", "unknown-state")
          .formParam("code", "some-code")
          .formParam("verifier", VERIFIER)
          .when()
          .post(relayUri)
          .then()
          .statusCode(404);
    }
  }
}
