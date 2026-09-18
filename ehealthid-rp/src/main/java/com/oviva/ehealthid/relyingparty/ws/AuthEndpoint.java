package com.oviva.ehealthid.relyingparty.ws;

import static com.oviva.ehealthid.relyingparty.svc.LocalizedException.Message;
import static com.oviva.ehealthid.relyingparty.util.LocaleUtils.getNegotiatedLocale;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.oviva.ehealthid.relyingparty.svc.AuthService;
import com.oviva.ehealthid.relyingparty.svc.AuthService.AuthorizationRequest;
import com.oviva.ehealthid.relyingparty.svc.AuthService.CallbackRequest;
import com.oviva.ehealthid.relyingparty.svc.AuthService.RelayRequest;
import com.oviva.ehealthid.relyingparty.svc.AuthService.SelectedIdpRequest;
import com.oviva.ehealthid.relyingparty.svc.ValidationException;
import com.oviva.ehealthid.relyingparty.ws.ui.Pages;
import com.oviva.ehealthid.relyingparty.ws.ui.TemplateRenderer;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.CookieParam;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.NewCookie.SameSite;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;
import jakarta.ws.rs.core.UriBuilder;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

@Path("/auth")
public class AuthEndpoint {
  private final Pages pages = new Pages(new TemplateRenderer());

  private final AuthService authService;
  private final URI appUri;
  private final URI appRelayUri;

  public AuthEndpoint(AuthService authService, @Nullable URI appUri) {
    this(authService, appUri, null);
  }

  /**
   * @param appRelayUri native app link that receives a sectoral IdP callback which reached another
   *     browser than the sign-in session (e.g. the insurer app opened Safari). Null disables the
   *     relay and keeps the plain cookie-bound callback.
   */
  public AuthEndpoint(AuthService authService, @Nullable URI appUri, @Nullable URI appRelayUri) {
    this.authService = authService;
    this.appUri = appUri;
    this.appRelayUri = appRelayUri;
  }

  // Authorization Request
  // https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
  @GET
  @Produces(MediaType.TEXT_HTML)
  public Response auth(
      @QueryParam("scope") String scope,
      @QueryParam("state") String state,
      @QueryParam("response_type") String responseType,
      @QueryParam("client_id") String clientId,
      @QueryParam("redirect_uri") String redirectUri,
      @QueryParam("nonce") String nonce,
      @HeaderParam("Accept-Language") @DefaultValue("de-DE") String acceptLanguage) {

    var uri = mustParse(redirectUri);

    var res =
        authService.auth(
            new AuthorizationRequest(scope, state, responseType, clientId, uri, nonce));

    var locale = getNegotiatedLocale(acceptLanguage);
    var form = pages.selectIdpForm(res.identityProviders(), appUri, locale);

    return Response.ok(form, MediaType.TEXT_HTML_TYPE)
        .cookie(createSessionCookie(res.sessionId()))
        .build();
  }

  @NonNull
  private URI mustParse(@Nullable String uri) {
    if (uri == null || uri.isBlank()) {
      var localizedMessage = new Message("error.blankUri");
      throw new ValidationException(localizedMessage);
    }
    try {
      return new URI(uri);
    } catch (URISyntaxException e) {
      var localizedMessage = new Message("error.badUri", uri);
      throw new ValidationException(localizedMessage);
    }
  }

  private NewCookie createSessionCookie(String sessionId) {
    return new NewCookie.Builder("session_id")
        .value(sessionId)
        .secure(true)
        .httpOnly(true)
        .sameSite(SameSite.LAX)
        .maxAge(-1) // session scoped
        .path("/auth")
        .build();
  }

  @POST
  @Path("/select-idp")
  @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
  @Produces(MediaType.TEXT_HTML)
  public Response postSelectIdp(
      @CookieParam("session_id") String sessionId,
      @FormParam("identityProvider") String identityProvider,
      @HeaderParam("Accept-Language") @DefaultValue("de-DE") String acceptLanguage) {

    var redirect =
        authService.selectedIdentityProvider(new SelectedIdpRequest(sessionId, identityProvider));

    var locale = getNegotiatedLocale(acceptLanguage);
    var page = pages.jumpToApp(redirect, appRelayUri != null, locale);

    return Response.ok(page, MediaType.TEXT_HTML_TYPE).build();
  }

  @GET
  @Path("/callback")
  @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
  @Produces(MediaType.TEXT_HTML)
  public Response callback(
      @CookieParam("session_id") String sessionId,
      @QueryParam("code") String code,
      @QueryParam("state") String state,
      @HeaderParam("Accept-Language") @DefaultValue("de-DE") String acceptLanguage) {

    if (appRelayUri != null && code != null && !code.isBlank()) {
      var relaySessionId = authService.findRelayableSessionId(state);
      if (relaySessionId != null && !relaySessionId.equals(sessionId)) {
        // This browser does not hold the sign-in session. Nothing is redeemed and no cookie is
        // set here; only the native app with a sign-in in progress may relay the callback.
        var link =
            UriBuilder.fromUri(appRelayUri)
                .queryParam("state", state)
                .queryParam("code", code)
                .build();
        var page = pages.returnToApp(link, getNegotiatedLocale(acceptLanguage));
        return noStore(Response.ok(page, MediaType.TEXT_HTML_TYPE)).build();
      }
    }

    return callback(sessionId, code, acceptLanguage);
  }

  public Response callback(String sessionId, String code, String acceptLanguage) {

    var redirectUri = authService.callback(new CallbackRequest(sessionId, code));
    var locale = getNegotiatedLocale(acceptLanguage);
    var successPage = pages.success(redirectUri, locale);

    return Response.ok(successPage, MediaType.TEXT_HTML_TYPE).build();
  }

  @POST
  @Path("/relay")
  @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
  public Response relay(@FormParam("state") String state, @FormParam("code") String code) {
    if (appRelayUri == null) {
      return Response.status(Status.NOT_FOUND).build();
    }
    authService.relayCallback(new RelayRequest(state, code));
    return noStore(Response.noContent()).build();
  }

  @GET
  @Path("/relay-status")
  @Produces(MediaType.APPLICATION_JSON)
  public Response relayStatus(@CookieParam("session_id") String sessionId) {
    if (appRelayUri == null) {
      return Response.status(Status.NOT_FOUND).build();
    }
    var body = new RelayStatus(authService.isRelayComplete(sessionId));
    return noStore(Response.ok(body, MediaType.APPLICATION_JSON_TYPE)).build();
  }

  @GET
  @Path("/continue")
  @Produces(MediaType.TEXT_HTML)
  public Response continueRelayed(
      @CookieParam("session_id") String sessionId,
      @HeaderParam("Accept-Language") @DefaultValue("de-DE") String acceptLanguage) {
    if (appRelayUri == null) {
      return Response.status(Status.NOT_FOUND).build();
    }
    var redirectUri = authService.continueRelayed(sessionId);
    var successPage = pages.success(redirectUri, getNegotiatedLocale(acceptLanguage));
    return noStore(Response.ok(successPage, MediaType.TEXT_HTML_TYPE)).build();
  }

  private static Response.ResponseBuilder noStore(Response.ResponseBuilder builder) {
    return builder.header("Cache-Control", "no-store").header("Referrer-Policy", "no-referrer");
  }

  public record RelayStatus(@JsonProperty("complete") boolean complete) {}

  public record AuthResponse(@JsonProperty("identity_providers") List<IdpEntry> identityProviders) {

    public record IdpEntry(
        @JsonProperty("iss") String iss,
        @JsonProperty("name") String name,
        @JsonProperty("logo_uri") String logoUrl) {}
  }
}
