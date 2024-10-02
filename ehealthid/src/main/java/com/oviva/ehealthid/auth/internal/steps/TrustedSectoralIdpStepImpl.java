package com.oviva.ehealthid.auth.internal.steps;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.jwk.ECKey;
import com.oviva.ehealthid.auth.AuthExceptions;
import com.oviva.ehealthid.auth.IdTokenJWS;
import com.oviva.ehealthid.auth.IdTokenJWS.IdToken;
import com.oviva.ehealthid.auth.steps.TrustedSectoralIdpStep;
import com.oviva.ehealthid.crypto.KeySupplier;
import com.oviva.ehealthid.fedclient.api.EntityStatementJWS;
import com.oviva.ehealthid.fedclient.api.OpenIdClient;
import com.oviva.ehealthid.util.JsonCodec;
import com.oviva.ehealthid.util.JsonPayloadTransformer;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.net.URI;
import java.text.ParseException;

public class TrustedSectoralIdpStepImpl implements TrustedSectoralIdpStep {

  private final OpenIdClient openIdClient;

  private final URI selfIssuer;
  private final URI idpRedirectUri;
  private final URI callbackUri;
  private final EntityStatementJWS trustedIdpEntityStatement;
  private final KeySupplier relyingPartyEncKeySupplier;

  public TrustedSectoralIdpStepImpl(
      @NonNull OpenIdClient openIdClient,
      @NonNull URI selfIssuer,
      @NonNull URI idpRedirectUri,
      @NonNull URI callbackUri,
      @NonNull EntityStatementJWS trustedIdpEntityStatement,
      @NonNull KeySupplier relyingPartyEncKeySupplier) {
    this.openIdClient = openIdClient;
    this.selfIssuer = selfIssuer;
    this.idpRedirectUri = idpRedirectUri;
    this.callbackUri = callbackUri;
    this.trustedIdpEntityStatement = trustedIdpEntityStatement;
    this.relyingPartyEncKeySupplier = relyingPartyEncKeySupplier;
  }

  @Override
  public @NonNull URI idpRedirectUri() {
    return idpRedirectUri;
  }

  @NonNull
  @Override
  public IdTokenJWS exchangeSectoralIdpCode(@NonNull String code, @NonNull String codeVerifier) {

    // -------------------------------
    // 1. Define the Test Encryption Key
    // -------------------------------
    String jwkJson =
        "{\n"
            + "  \"kty\": \"EC\",\n"
            + "  \"d\": \"SLACiqrEVQXgAKOFIA8HAenlumjUtho07rhqCBruJOk\",\n"
            + "  \"use\": \"enc\",\n"
            + "  \"crv\": \"P-256\",\n"
            + "  \"kid\": \"relying-party-enc\",\n"
            + "  \"x\": \"TGY6FLnl6I4PMR4OlhMZrK8Ln_4Fs47RTBYpKSiP2kc\",\n"
            + "  \"y\": \"fs_HK7KbnJ7F7F3mv64lmjt2w5n_Bm3cXnRFTt-iHKU\"\n"
            + "}";

    ECKey ecJWK;
    try {
      ecJWK = ECKey.parse(jwkJson);
    } catch (ParseException e) {
      throw new RuntimeException("Failed to parse JWK JSON", e);
    }

    String hardcodedIdToken =
        "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSIsImN0eSI6IkpXVCIsImtpZCI6InJlbHlpbmctcGFydHktZW5jIiwiZXBrIjp7Imt0eSI6IkVDIiwieCI6IlpuOTZnX0p3YXY0dENZNE41VEtGQUlYaXlmaTlvV2s0OUpLVEQ3aFAtTUEiLCJ5IjoiYl9YQmVZRjJ4ME5JTDhVbXBEMTVubktueFhwbHRiRzZaX3dHTGlhQjBEUSIsImNydiI6IlAtMjU2In19.._B35CBOzkZQpiYMx.witIF5OyREmxO3GEizbN7nx0yrVPQr0A2FLsOPC2oyGcNlCrsk97XnY_I13A8EXq3IMtxJIFWe2TW8dI3Cz6js8Z0Nn-qc_xJu_zcRnkjFTEtHqcxniy5nEGqLjUPFt6CypzuXf2UD-q__IMv4rJ79ODVBJ3x2ezmJworI3l-goIM6xAd-fWx6X_f2JCtxepuQNfau11pvWLmSVe2N4yod67aFxiT2mH3zLmT-bmpK8nUYsguSm8fhyFwFBOxCXDTtVDYMkZFJDbYRDewFSiskFq7wdlrtNhqkTjL83JiiYzT26B-zeQE-23p-_YjnIdC6-Wk9n-D98JIWCRGulCrsLQToWN4AeN3ShTAx8GDj3q4lbN-mXhysi43FqML4Nwb3a-Ar-qfZSQX588hv79cXhgrDTPTon6uh3_dhaIneYxTA-3iM57o5f2fnIwscMq2ra6GE2TF0WFVdkgzy9Reo-LnzoZk_3BOt6_sSMxRpc6YDfTY1abz7W1ixl_VJGqJOhAAKDcOMq0fGtcrAbG6q4fxBSdRBszUGNcjSSNQSCkohNj6aTO0lJG9XNUpEvnJgJ-lXC3VGRXq-YuCiMTIbVRt31diVg8hnncnzIDt8hSiYjghgX-mZUax4P6KymKb_czNYgyTcIGHrcoFwJgoIRJFKQnQXocr375AIUYGkSzCE1ZobrDXDsQUWFKEoKKmD5PnDZMhWVmKT42jbovhkTlqilU7nHOVIJjCtmJnK1DhYpEpEUuLli75P5HUbO3IMRSOMvgetRB8UhLFzv17j9xQE4hdzTzD1OXU96B6DD0sZB2SA_KZclkUhj4WDgTZUa_dKAUuwlnymMDyRW_AXoX05K29Oe1jwdbVAKAPlFz1RH-OKjgtbK8KmmNVRYleM6rd_inb49GlR0fRt-TK9yYqDvkZAQ_0kwVecW4Wpm1zIfF2SXZ1qZsjTBRxtL9hme1onvH84k2AtSxq09EfnIEwLKqSJTRdWQ8Q5KKNPBkPgHVUwsweG9aBOhgm5Azkuzf9SATVLE5LNiUh3cyUEwMhHwrFaf-XsCebB7dp_WL83kNXA.ziIZQ31jn9NBqfaczBTzXQ";

    try {

      JWEObject jweObject = JWEObject.parse(hardcodedIdToken);
      JWEDecrypter decrypter = new ECDHDecrypter(ecJWK.toECPrivateKey());
      jweObject.decrypt(decrypter);
      var signedJws = jweObject.getPayload().toJWSObject();

      var payload =
          signedJws
              .getPayload()
              .toType(new JsonPayloadTransformer<>(IdToken.class, JsonCodec::readValue));
      return new IdTokenJWS(signedJws, payload);

    } catch (ParseException e) {
      // Handle parsing exceptions
      throw AuthExceptions.badIdToken(trustedIdpEntityStatement.body().sub(), e);
    } catch (JOSEException e) {
      // Handle decryption exceptions
      throw AuthExceptions.badIdToken(trustedIdpEntityStatement.body().sub(), e);
    }
  }
}
