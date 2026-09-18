package com.oviva.ehealthid.relyingparty.ws;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import com.oviva.ehealthid.relyingparty.svc.AuthService;
import com.oviva.ehealthid.relyingparty.svc.AuthService.AuthorizationRequest;
import com.oviva.ehealthid.relyingparty.svc.AuthService.AuthorizationResponse;
import com.oviva.ehealthid.relyingparty.svc.AuthService.CallbackRequest;
import com.oviva.ehealthid.relyingparty.svc.AuthService.RelayRequest;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response.Status;
import java.net.URI;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class AuthEndpointRelayTest {

  private static final URI RELAY_URI = URI.create("diga.staging.smokefreeapp://healthid_return");
  private static final URI BROKER = URI.create("https://iam.example.com/broker/endpoint?code=x");

  private final AuthService authService = mock(AuthService.class);

  @Test
  void callbackInOtherBrowser_rendersAppLinkWithoutCookieOrRedemption() {
    when(authService.findRelayableSessionId("up")).thenReturn("sid");
    var sut = new AuthEndpoint(authService, null, RELAY_URI);

    try (var res = sut.callback(null, "c+/=", "up", "de-DE")) {
      assertEquals(Status.OK.getStatusCode(), res.getStatus());
      assertNull(res.getHeaderString(HttpHeaders.SET_COOKIE));
      assertTrue(res.getCookies().isEmpty());
      assertEquals("no-store", res.getHeaderString("Cache-Control"));
      assertEquals("no-referrer", res.getHeaderString("Referrer-Policy"));
      var page = (String) res.getEntity();
      assertTrue(
          unescapeHtml(page)
              .contains(
                  "href=\"diga.staging.smokefreeapp://healthid_return?state=up&code=c%2B%2F%3D\""),
          page);
      assertTrue(page.contains("Zurück zur App"));
    }
    verify(authService, never()).callback(any());
    verify(authService, never()).relayCallback(any());
  }

  @Test
  void callbackWithStaleOtherCookie_isAlsoHandedToApp() {
    when(authService.findRelayableSessionId("up")).thenReturn("sid");
    var sut = new AuthEndpoint(authService, null, RELAY_URI);

    try (var res = sut.callback("stale-sid", "code", "up", "en-US")) {
      assertTrue(((String) res.getEntity()).contains("healthid_return"));
    }
    verify(authService, never()).callback(any());
  }

  @Test
  void callbackInSigningInBrowser_keepsCookieBoundPath() {
    when(authService.findRelayableSessionId("up")).thenReturn("sid");
    when(authService.callback(any())).thenReturn(BROKER);
    var sut = new AuthEndpoint(authService, null, RELAY_URI);

    try (var res = sut.callback("sid", "code", "up", "de-DE")) {
      assertTrue(((String) res.getEntity()).contains(BROKER.getHost()));
    }
    var captor = ArgumentCaptor.forClass(CallbackRequest.class);
    verify(authService).callback(captor.capture());
    assertEquals("sid", captor.getValue().sessionId());
  }

  @Test
  void relayDisabled_keepsExistingCallbackBehaviour() {
    when(authService.callback(any())).thenReturn(BROKER);
    var sut = new AuthEndpoint(authService, null);

    try (var res = sut.callback(null, "code", "up", "de-DE")) {
      assertEquals(Status.OK.getStatusCode(), res.getStatus());
    }
    verify(authService).callback(new CallbackRequest(null, "code"));
    verify(authService, never()).findRelayableSessionId(any());

    try (var res = sut.relay("up", "code", "verifier")) {
      assertEquals(Status.NOT_FOUND.getStatusCode(), res.getStatus());
    }
    try (var res = sut.relayStatus("sid")) {
      assertEquals(Status.NOT_FOUND.getStatusCode(), res.getStatus());
    }
    try (var res = sut.continueRelayed("sid", "de-DE")) {
      assertEquals(Status.NOT_FOUND.getStatusCode(), res.getStatus());
    }
    verify(authService, never()).relayCallback(any());
    verify(authService, never()).continueRelayed(any());
  }

  @Test
  void unknownStateOrMissingCode_fallsBackToCookieBoundPath() {
    when(authService.callback(any())).thenReturn(BROKER);
    var sut = new AuthEndpoint(authService, null, RELAY_URI);

    try (var res = sut.callback(null, "code", "unknown", "de-DE")) {
      assertFalse(((String) res.getEntity()).contains("healthid_return"));
    }
    try (var res = sut.callback(null, null, "up", "de-DE")) {
      assertFalse(((String) res.getEntity()).contains("healthid_return"));
    }
    verify(authService, times(2)).callback(any());
  }

  @Test
  void relay_passesStateAndCode() {
    var sut = new AuthEndpoint(authService, null, RELAY_URI);
    try (var res = sut.relay("up", "code", "verifier")) {
      assertEquals(Status.NO_CONTENT.getStatusCode(), res.getStatus());
      assertNull(res.getHeaderString(HttpHeaders.SET_COOKIE));
    }
    verify(authService).relayCallback(new RelayRequest("up", "code", "verifier"));
  }

  @Test
  void relayStatusAndContinue_areCookieBound() {
    when(authService.isRelayComplete("sid")).thenReturn(true);
    when(authService.continueRelayed("sid")).thenReturn(BROKER);
    var sut = new AuthEndpoint(authService, null, RELAY_URI);

    try (var res = sut.relayStatus("sid")) {
      assertEquals(new AuthEndpoint.RelayStatus(true), res.getEntity());
      assertEquals("no-store", res.getHeaderString("Cache-Control"));
    }
    try (var res = sut.relayStatus(null)) {
      assertEquals(new AuthEndpoint.RelayStatus(false), res.getEntity());
    }
    try (var res = sut.continueRelayed("sid", "de-DE")) {
      assertTrue(((String) res.getEntity()).contains(BROKER.getHost()));
    }
  }

  @Test
  void selectIdp_pollsForRelayOnlyWhenEnabled() {
    when(authService.selectedIdentityProvider(any())).thenReturn(URI.create("https://idp.example"));

    try (var res = new AuthEndpoint(authService, null, RELAY_URI).postSelectIdp("s", "i", "de")) {
      assertTrue(((String) res.getEntity()).contains("/auth/relay-status"));
    }
    try (var res = new AuthEndpoint(authService, null).postSelectIdp("s", "i", "de")) {
      assertFalse(((String) res.getEntity()).contains("/auth/relay-status"));
    }
  }

  @Test
  void auth_forwardsAppRelayChallengeOnlyWhenRelayEnabled() {
    when(authService.auth(any())).thenReturn(new AuthorizationResponse(List.of(), "sid"));
    var redirect = "https://iam.example.com/broker/cb";
    var captor = ArgumentCaptor.forClass(AuthorizationRequest.class);

    try (var res =
        new AuthEndpoint(authService, null, RELAY_URI)
            .auth("openid", "s", "code", "c", redirect, "n", "challenge", "de-DE")) {
      assertEquals(Status.OK.getStatusCode(), res.getStatus());
    }
    try (var res =
        new AuthEndpoint(authService, null)
            .auth("openid", "s", "code", "c", redirect, "n", "challenge", "de-DE")) {
      assertEquals(Status.OK.getStatusCode(), res.getStatus());
    }

    verify(authService, times(2)).auth(captor.capture());
    assertEquals("challenge", captor.getAllValues().get(0).appRelayChallenge());
    assertNull(captor.getAllValues().get(1).appRelayChallenge());
  }

  // mustache.java escapes attribute values numerically; browsers decode them the same way.
  private static String unescapeHtml(String html) {
    var m = java.util.regex.Pattern.compile("&#(\\d+);").matcher(html);
    var out = new StringBuilder();
    while (m.find()) {
      m.appendReplacement(
          out,
          java.util.regex.Matcher.quoteReplacement(
              String.valueOf((char) Integer.parseInt(m.group(1)))));
    }
    m.appendTail(out);
    return out.toString().replace("&amp;", "&").replace("&quot;", "\"");
  }
}
