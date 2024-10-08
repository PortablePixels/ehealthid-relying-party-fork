package com.oviva.ehealthid.relyingparty.svc;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.text.ParseException;
import java.util.List;

public class ClientKeyStore {

  private final ECKey signingKey;

  public ClientKeyStore() {

    try {
      this.signingKey =
          ECKey.parse(
              """
{"kty":"EC","x":"HLblHnHYJsb1LQQSK-o13X4cJl_CJJBhA_qFtZn2cB0","y":"JO17uPvxetyheCXnpVnJX-sKycau6G-b7S0U1QXVFbs","crv":"P-256","kid":"e3xgsgiETxx6YJEUY3Kogaml59sjDtV6OCXOAR-biYs","use":"sig","alg":"ES256"}
  """);
    } catch (ParseException e) {
      throw new IllegalStateException("failed to parse client signing key", e);
    }
  }

  public ECKey signingKey() {
    return signingKey;
  }

  public record StaticJwkSource<T extends SecurityContext>(JWK key) implements JWKSource<T> {

    @Override
    public List<JWK> get(JWKSelector jwkSelector, T context) throws KeySourceException {
      return jwkSelector.select(new JWKSet(key));
    }
  }
}
