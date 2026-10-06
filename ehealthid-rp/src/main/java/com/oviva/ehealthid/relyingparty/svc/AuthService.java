package com.oviva.ehealthid.relyingparty.svc;

import com.oviva.ehealthid.auth.AuthenticationFlow;
import com.oviva.ehealthid.fedclient.IdpEntry;
import com.oviva.ehealthid.relyingparty.cfg.RelyingPartyConfig;
import com.oviva.ehealthid.relyingparty.fed.FederationConfig;
import com.oviva.ehealthid.relyingparty.svc.LocalizedException.Message;
import com.oviva.ehealthid.relyingparty.svc.OpenIdErrors.ErrorCode;
import com.oviva.ehealthid.relyingparty.svc.SessionRepo.Session;
import com.oviva.ehealthid.relyingparty.util.IdGenerator;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import jakarta.ws.rs.core.UriBuilder;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AuthService {

  private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

  private final URI baseUri;
  private final RelyingPartyConfig relyingPartyConfig;

  private final SessionRepo sessionRepo;
  private final TokenIssuer tokenIssuer;

  private final AuthenticationFlow authenticationFlow;

  private final FederationConfig federationConfig;

  public AuthService(
      URI baseUri,
      RelyingPartyConfig relyingPartyConfig,
      FederationConfig federationConfig,
      SessionRepo sessionRepo,
      TokenIssuer tokenIssuer,
      AuthenticationFlow authenticationFlow) {
    this.baseUri = baseUri;
    this.relyingPartyConfig = relyingPartyConfig;
    this.federationConfig = federationConfig;
    this.sessionRepo = sessionRepo;
    this.tokenIssuer = tokenIssuer;
    this.authenticationFlow = authenticationFlow;
  }

  private static String calculateS256CodeChallenge(String codeVerifier) {
    try {
      var digest = MessageDigest.getInstance("SHA-256");
      var hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
      return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  private static String generatePkceCodeVerifier() {
    var rng = new SecureRandom();

    // https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
    var bytes = new byte[32];
    rng.nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  // Authorization Request
  // https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
  @NonNull
  public AuthorizationResponse auth(@NonNull AuthorizationRequest request) {

    validateAuthorizationRequest(request);

    var verifier = generatePkceCodeVerifier();

    var codeChallenge = calculateS256CodeChallenge(verifier);

    var relyingPartyCallback = baseUri.resolve("/auth/callback");

    // Our own state towards the sectoral IdP, so a callback can be matched to its session
    // without relying on the IdP's state value.
    var upstreamState = IdGenerator.generateID();

    var step1 =
        authenticationFlow.start(
            new AuthenticationFlow.Session(
                upstreamState,
                request.nonce(),
                relyingPartyCallback,
                codeChallenge,
                federationConfig.scopes()));

    var identityProviders = step1.fetchIdpOptions();

    var sessionId = IdGenerator.generateID();
    var session =
        Session.create()
            .id(sessionId)
            .state(request.state())
            .nonce(request.nonce())
            .redirectUri(request.redirectUri())
            .clientId(request.clientId())
            .codeVerifier(verifier)
            .selectSectoralIdpStep(step1)
            .upstreamState(upstreamState)
            .appRelayChallenge(validRelayChallenge(request.appRelayChallenge()))
            .build();

    sessionRepo.save(session);

    return new AuthorizationResponse(identityProviders, sessionId);
  }

  @NonNull
  public URI selectedIdentityProvider(@NonNull SelectedIdpRequest request) {

    var selectedIdp = request.selectedIdentityProvider();
    if (selectedIdp == null || selectedIdp.isBlank()) {
      throw new ValidationException(new Message("error.noProvider"));
    }

    var session = mustFindSession(request.sessionId());

    var step2 = session.selectSectoralIdpStep().redirectToSectoralIdp(selectedIdp);

    var federatedLogin = step2.idpRedirectUri();

    var newSession = session.toBuilder().trustedSectoralIdpStep(step2).build();

    sessionRepo.save(newSession);

    return federatedLogin;
  }

  @NonNull
  public URI callback(@NonNull CallbackRequest request) {

    validateCallbackRequest(request);

    var session = mustFindSession(request.sessionId());

    var idToken =
        session
            .trustedSectoralIdpStep()
            .exchangeSectoralIdpCode(request.code(), session.codeVerifier());

    session = removeSession(request.sessionId());
    if (session == null) {
      throw new ValidationException(new Message("error.invalidSession"));
    }

    var issued = tokenIssuer.issueCode(session, idToken);

    return UriBuilder.fromUri(session.redirectUri())
        .queryParam("code", issued.code())
        .queryParam("state", session.state())
        .build();
  }

  /**
   * Returns the session awaiting a sectoral IdP callback for {@code upstreamState}, or null. A
   * callback without the matching session cookie (e.g. the insurer app opened Safari instead of the
   * app's sign-in session) must never complete that session here: it can only be handed to the
   * native app, which relays it while its own sign-in is in progress.
   */
  @Nullable
  public String findRelayableSessionId(@Nullable String upstreamState) {
    var session = findAwaitingRelay(upstreamState);
    return session == null ? null : session.id();
  }

  /**
   * Accepts a callback relayed by the native app. The code is redeemed immediately, but the session
   * only continues in the browser that holds its session cookie (see {@link
   * #continueRelayed(String)}).
   */
  public void relayCallback(@NonNull RelayRequest request) {
    if (request.code() == null || request.code().isBlank()) {
      throw new ValidationException(new Message("error.invalidCallback"));
    }
    var session = findAwaitingRelay(request.upstreamState());
    var refusal = relayRefusal(session, request.appRelayVerifier());
    if (refusal != null) {
      // The 400 alone does not say which check failed; only the reason is logged, never a value.
      logger.warn("relay refused: {}", refusal);
      throw new ValidationException(new Message("error.invalidSession"));
    }

    var idToken =
        session
            .trustedSectoralIdpStep()
            .exchangeSectoralIdpCode(request.code(), session.codeVerifier());

    sessionRepo.save(session.toBuilder().relayedIdToken(idToken).build());
  }

  public boolean isRelayComplete(@Nullable String sessionId) {
    if (sessionId == null || sessionId.isBlank()) {
      return false;
    }
    var session = sessionRepo.load(sessionId);
    return session != null && session.relayedIdToken() != null;
  }

  @NonNull
  public URI continueRelayed(@Nullable String sessionId) {
    var session = mustFindSession(sessionId);
    if (session.relayedIdToken() == null) {
      throw new ValidationException(new Message("error.invalidSession"));
    }

    session = removeSession(sessionId);
    if (session == null || session.relayedIdToken() == null) {
      throw new ValidationException(new Message("error.invalidSession"));
    }

    var issued = tokenIssuer.issueCode(session, session.relayedIdToken());

    return UriBuilder.fromUri(session.redirectUri())
        .queryParam("code", issued.code())
        .queryParam("state", session.state())
        .build();
  }

  // Same shape as a PKCE S256 challenge: 32 bytes, base64url without padding.
  @Nullable
  private static String validRelayChallenge(@Nullable String challenge) {
    if (challenge == null || !challenge.matches("[A-Za-z0-9_-]{43}")) {
      return null;
    }
    return challenge;
  }

  @Nullable
  static String relayRefusal(@Nullable Session session, @Nullable String verifier) {
    if (session == null) {
      return "no session awaiting a relay for this state";
    }
    if (session.appRelayChallenge() == null) {
      return "session has no app relay challenge";
    }
    if (!matchesRelayChallenge(session.appRelayChallenge(), verifier)) {
      return "verifier does not match the session's app relay challenge";
    }
    return null;
  }

  // The app keeps the verifier and sends only its hash through the browser, so a leaked sign-in
  // URL does not allow relaying. Sessions without a challenge can never be relayed.
  private static boolean matchesRelayChallenge(
      @Nullable String challenge, @Nullable String verifier) {
    if (challenge == null || verifier == null || !verifier.matches("[A-Za-z0-9_-]{43,128}")) {
      return false;
    }
    return MessageDigest.isEqual(
        challenge.getBytes(StandardCharsets.US_ASCII),
        calculateS256CodeChallenge(verifier).getBytes(StandardCharsets.US_ASCII));
  }

  @Nullable
  private Session findAwaitingRelay(@Nullable String upstreamState) {
    if (upstreamState == null || upstreamState.isBlank()) {
      return null;
    }
    var session = sessionRepo.findByUpstreamState(upstreamState);
    if (session == null
        || session.trustedSectoralIdpStep() == null
        || session.relayedIdToken() != null) {
      return null;
    }
    return session;
  }

  private void validateCallbackRequest(CallbackRequest request) {
    if (request.code() == null
        || request.code().isBlank()
        || request.sessionId() == null
        || request.sessionId().isBlank()) {
      throw new ValidationException(new Message("error.invalidCallback"));
    }
  }

  @Nullable
  private Session removeSession(@Nullable String id) {

    if (id == null || id.isBlank()) {
      return null;
    }

    return sessionRepo.remove(id);
  }

  @NonNull
  private Session mustFindSession(@Nullable String id) {
    var localizedMessage = new Message("error.invalidSession");
    if (id == null || id.isBlank()) {
      throw new ValidationException(localizedMessage);
    }

    var session = sessionRepo.load(id);
    if (session == null) {
      throw new ValidationException(localizedMessage);
    }
    return session;
  }

  private void validateAuthorizationRequest(AuthorizationRequest request) {

    var redirect = request.redirectUri();

    if (redirect == null) {
      throw new ValidationException(new Message("error.noRedirect"));
    }

    if (!"https".equals(redirect.getScheme())) {
      var localizedMessage = new Message("error.insecureRedirect", redirect.toString());
      throw new ValidationException(localizedMessage);
    }

    if (!relyingPartyConfig.validRedirectUris().contains(redirect)) {
      var localizedMessage = new Message("error.untrustedRedirect", redirect.toString());
      throw new ValidationException(localizedMessage);
    }

    if (!"openid".equals(request.scope())) {
      var localizedErrorMessage = new Message("error.unsupportedScope", request.scope());
      var uri =
          OpenIdErrors.redirectWithError(
              redirect,
              ErrorCode.INVALID_SCOPE,
              request.state(),
              localizedErrorMessage.messageKey());
      throw new ValidationException(localizedErrorMessage, uri);
    }

    var responseType = request.responseType();
    if (responseType == null
        || !relyingPartyConfig.supportedResponseTypes().contains(responseType)) {
      var localizedErrorMessage = new Message("error.unsupportedResponseType", responseType);
      var uri =
          OpenIdErrors.redirectWithError(
              redirect,
              ErrorCode.UNSUPPORTED_RESPONSE_TYPE,
              request.state(),
              localizedErrorMessage.messageKey());
      throw new ValidationException(localizedErrorMessage, uri);
    }
  }

  public record SelectedIdpRequest(String sessionId, String selectedIdentityProvider) {}

  public record CallbackRequest(String sessionId, String code) {}

  public record RelayRequest(String upstreamState, String code, String appRelayVerifier) {}

  /**
   * @param appRelayChallenge S256 hash of a secret held by the native app that started this sign-in
   *     (forwarded by the broker). Only the holder of that secret may relay a callback for this
   *     session; without it the relay is refused.
   */
  public record AuthorizationRequest(
      String scope,
      String state,
      String responseType,
      String clientId,
      URI redirectUri,
      String nonce,
      String appRelayChallenge) {

    public AuthorizationRequest(
        String scope,
        String state,
        String responseType,
        String clientId,
        URI redirectUri,
        String nonce) {
      this(scope, state, responseType, clientId, redirectUri, nonce, null);
    }
  }

  public record AuthorizationResponse(List<IdpEntry> identityProviders, String sessionId) {}
}
