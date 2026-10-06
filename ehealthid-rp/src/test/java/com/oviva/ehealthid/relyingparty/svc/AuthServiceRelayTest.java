package com.oviva.ehealthid.relyingparty.svc;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.oviva.ehealthid.auth.AuthenticationFlow;
import com.oviva.ehealthid.auth.IdTokenJWS;
import com.oviva.ehealthid.auth.steps.SelectSectoralIdpStep;
import com.oviva.ehealthid.auth.steps.TrustedSectoralIdpStep;
import com.oviva.ehealthid.relyingparty.cfg.RelyingPartyConfig;
import com.oviva.ehealthid.relyingparty.fed.FederationConfig;
import com.oviva.ehealthid.relyingparty.svc.AuthService.AuthorizationRequest;
import com.oviva.ehealthid.relyingparty.svc.AuthService.RelayRequest;
import com.oviva.ehealthid.relyingparty.svc.SessionRepo.Session;
import com.oviva.ehealthid.relyingparty.svc.TokenIssuer.Code;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class AuthServiceRelayTest {

  private static final URI BASE_URI = URI.create("https://idp.example.com");
  private static final URI REDIRECT_URI = URI.create("https://myapp.example.com");
  private static final String UPSTREAM_STATE = "upstream-state-0123456789abcdef0123456789abc";
  // APP_CHALLENGE = BASE64URL(SHA256(APP_VERIFIER)), as for PKCE S256.
  private static final String APP_VERIFIER = "relay-verifier-0123456789abcdefghijklmnopqrs";
  private static final String APP_CHALLENGE = "Hrs_ghO0hKfe2uEqJOUaFLr-rBFottVWVO-EZjh9tW4";

  private final CaffeineSessionRepo sessionRepo =
      new CaffeineSessionRepo(
          Caffeine.newBuilder().<String, Session>build(), Duration.ofMinutes(5));
  private final TokenIssuer tokenIssuer = mock(TokenIssuer.class);
  private final TrustedSectoralIdpStep trustedStep = mock(TrustedSectoralIdpStep.class);
  private final IdTokenJWS idToken = new IdTokenJWS(null, null);

  private AuthService sut() {
    var config = new RelyingPartyConfig(List.of("code"), List.of(REDIRECT_URI));
    return new AuthService(BASE_URI, config, null, sessionRepo, tokenIssuer, null);
  }

  private void saveAwaitingSession(String id) {
    sessionRepo.save(
        Session.create()
            .id(id)
            .state("keycloak-state")
            .redirectUri(REDIRECT_URI)
            .codeVerifier("verifier")
            .trustedSectoralIdpStep(trustedStep)
            .upstreamState(UPSTREAM_STATE)
            .appRelayChallenge(APP_CHALLENGE)
            .build());
  }

  private static RelayRequest relay(String state, String code) {
    return new RelayRequest(state, code, APP_VERIFIER);
  }

  @Test
  void auth_sendsOwnRandomStateUpstream() {
    var flow = mock(AuthenticationFlow.class);
    var step1 = mock(SelectSectoralIdpStep.class);
    when(flow.start(any())).thenReturn(step1);
    when(step1.fetchIdpOptions()).thenReturn(List.of());
    var fed = FederationConfig.create().scopes(List.of("openid")).build();
    var repo = mock(SessionRepo.class);
    var config = new RelyingPartyConfig(List.of("code"), List.of(REDIRECT_URI));
    var sut = new AuthService(BASE_URI, config, fed, repo, null, flow);

    sut.auth(new AuthorizationRequest("openid", "keycloak-state", "code", "c", REDIRECT_URI, "n"));

    var flowSession = ArgumentCaptor.forClass(AuthenticationFlow.Session.class);
    verify(flow).start(flowSession.capture());
    var saved = ArgumentCaptor.forClass(Session.class);
    verify(repo).save(saved.capture());

    var upstream = flowSession.getValue().state();
    assertNotEquals("keycloak-state", upstream);
    assertTrue(upstream.length() >= 43, "256 bit random state");
    assertEquals(upstream, saved.getValue().upstreamState());
    assertEquals("keycloak-state", saved.getValue().state());
  }

  @Test
  void relay_redeemsCodeButOnlyCookieHolderContinues() {
    saveAwaitingSession("sid");
    when(trustedStep.exchangeSectoralIdpCode("code", "verifier")).thenReturn(idToken);
    when(tokenIssuer.issueCode(any(), eq(idToken)))
        .thenReturn(new Code("rp-code", null, null, REDIRECT_URI, null, null, idToken));
    var sut = sut();

    assertEquals("sid", sut.findRelayableSessionId(UPSTREAM_STATE));
    assertFalse(sut.isRelayComplete("sid"));

    sut.relayCallback(relay(UPSTREAM_STATE, "code"));

    assertTrue(sut.isRelayComplete("sid"));
    assertFalse(sut.isRelayComplete("other"));
    assertFalse(sut.isRelayComplete(null));
    assertNull(sut.findRelayableSessionId(UPSTREAM_STATE), "relay is one-shot");
    assertThrows(ValidationException.class, () -> sut.continueRelayed("other"));

    var redirect = sut.continueRelayed("sid");
    assertEquals(
        "https://myapp.example.com?code=rp-code&state=keycloak-state", redirect.toString());

    assertNull(sessionRepo.load("sid"), "session is consumed");
    assertThrows(ValidationException.class, () -> sut.continueRelayed("sid"));
  }

  @Test
  void relay_rejectsUnknownStateBlankCodeAndReplay() {
    saveAwaitingSession("sid");
    when(trustedStep.exchangeSectoralIdpCode("code", "verifier")).thenReturn(idToken);
    var sut = sut();

    assertThrows(ValidationException.class, () -> sut.relayCallback(relay("wrong", "code")));
    assertThrows(ValidationException.class, () -> sut.relayCallback(relay(null, "code")));
    assertThrows(ValidationException.class, () -> sut.relayCallback(relay(UPSTREAM_STATE, " ")));
    assertThrows(ValidationException.class, () -> sut.relayCallback(relay(UPSTREAM_STATE, null)));
    verifyNoInteractions(trustedStep);

    sut.relayCallback(relay(UPSTREAM_STATE, "code"));
    assertThrows(ValidationException.class, () -> sut.relayCallback(relay(UPSTREAM_STATE, "code")));
    verify(trustedStep, times(1)).exchangeSectoralIdpCode(any(), any());
  }

  @Test
  void relay_requiresTheVerifierOfTheAppThatStartedTheSignIn() {
    saveAwaitingSession("sid");
    var sut = sut();

    for (var verifier :
        new String[] {
          null, "", APP_CHALLENGE, "relay-verifier-0123456789abcdefghijklmnopqrt", "a b"
        }) {
      assertThrows(
          ValidationException.class,
          () -> sut.relayCallback(new RelayRequest(UPSTREAM_STATE, "code", verifier)),
          String.valueOf(verifier));
    }
    verifyNoInteractions(trustedStep);
    assertEquals("sid", sut.findRelayableSessionId(UPSTREAM_STATE), "still awaiting relay");
  }

  @Test
  void relay_isRefusedForSessionsStartedWithoutAppChallenge() {
    sessionRepo.save(
        Session.create()
            .id("sid")
            .codeVerifier("verifier")
            .trustedSectoralIdpStep(trustedStep)
            .upstreamState(UPSTREAM_STATE)
            .build());
    var sut = sut();

    assertThrows(ValidationException.class, () -> sut.relayCallback(relay(UPSTREAM_STATE, "code")));
    verifyNoInteractions(trustedStep);
  }

  @Test
  void auth_keepsOnlyWellFormedAppChallenge() {
    var flow = mock(AuthenticationFlow.class);
    var step1 = mock(SelectSectoralIdpStep.class);
    when(flow.start(any())).thenReturn(step1);
    when(step1.fetchIdpOptions()).thenReturn(List.of());
    var fed = FederationConfig.create().scopes(List.of("openid")).build();
    var repo = mock(SessionRepo.class);
    var config = new RelyingPartyConfig(List.of("code"), List.of(REDIRECT_URI));
    var sut = new AuthService(BASE_URI, config, fed, repo, null, flow);

    sut.auth(
        new AuthorizationRequest("openid", "s", "code", "c", REDIRECT_URI, "n", APP_CHALLENGE));
    sut.auth(new AuthorizationRequest("openid", "s", "code", "c", REDIRECT_URI, "n", "short"));

    var saved = ArgumentCaptor.forClass(Session.class);
    verify(repo, times(2)).save(saved.capture());
    assertEquals(APP_CHALLENGE, saved.getAllValues().get(0).appRelayChallenge());
    assertNull(saved.getAllValues().get(1).appRelayChallenge());
  }

  @Test
  void relay_rejectsSessionThatHasNotSelectedAnIdp() {
    sessionRepo.save(Session.create().id("sid").upstreamState(UPSTREAM_STATE).build());
    var sut = sut();

    assertNull(sut.findRelayableSessionId(UPSTREAM_STATE));
    assertThrows(ValidationException.class, () -> sut.relayCallback(relay(UPSTREAM_STATE, "code")));
  }

  @Test
  void relay_failedExchangeLeavesSessionIncomplete() {
    saveAwaitingSession("sid");
    when(trustedStep.exchangeSectoralIdpCode("code", "verifier"))
        .thenThrow(new RuntimeException("rejected"));
    var sut = sut();

    assertThrows(RuntimeException.class, () -> sut.relayCallback(relay(UPSTREAM_STATE, "code")));
    assertFalse(sut.isRelayComplete("sid"));
    assertThrows(ValidationException.class, () -> sut.continueRelayed("sid"));
  }

  @Test
  void relayRefusal_namesWhichCheckFailed() {
    var awaiting =
        Session.create()
            .id("s")
            .trustedSectoralIdpStep(trustedStep)
            .upstreamState(UPSTREAM_STATE)
            .appRelayChallenge(APP_CHALLENGE)
            .build();

    assertNull(AuthService.relayRefusal(awaiting, APP_VERIFIER));
    assertEquals(
        "no session awaiting a relay for this state", AuthService.relayRefusal(null, APP_VERIFIER));
    assertEquals(
        "session has no app relay challenge",
        AuthService.relayRefusal(awaiting.toBuilder().appRelayChallenge(null).build(), APP_VERIFIER));
    assertEquals(
        "verifier does not match the session's app relay challenge",
        AuthService.relayRefusal(awaiting, APP_VERIFIER.replace('r', 'x')));
  }
}
