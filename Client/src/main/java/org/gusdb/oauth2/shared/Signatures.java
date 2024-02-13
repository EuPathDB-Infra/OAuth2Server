package org.gusdb.oauth2.shared;

import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonStructure;
import javax.json.JsonWriter;
import javax.json.stream.JsonGenerator;

import org.apache.logging.log4j.LogManager;
import org.gusdb.oauth2.exception.CryptoException;
import org.gusdb.oauth2.shared.ECPublicKeyRepresentation.ECCoordinateStrings;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.crypto.EllipticCurveProvider;
import io.jsonwebtoken.security.Keys;

public class Signatures {

  public static final SignatureAlgorithm SECRET_KEY_ALGORITHM = SignatureAlgorithm.HS512;
  public static final SignatureAlgorithm ASYMMETRIC_KEY_ALGORITHM = SignatureAlgorithm.ES512;

  public static final TokenSigner SECRET_KEY_SIGNER = Signatures::createJwtFromJsonHmac;
  public static final TokenSigner ASYMMETRIC_KEY_SIGNER = Signatures::createJwtFromJsonEcdsa;

  private static final int MINIMUM_SEED_LENGTH = 16;

  public interface TokenSigner {
    /**
     * Takes a JSON object representing a JWT and produces a JWS (i.e. signed JWT).  The
     * signing strategy decides how to procure a key from the passed config and token data.
     *
     * @param tokenJson raw JSON that constitutes the JWT (claims as properties)
     * @param keyStore set of signing keys for this application
     * @param clientId client ID
     * @param clientSecret client secret
     * @return signed token string
     */
    String getSignedEncodedToken(JsonObject tokenJson, SigningKeyStore keyStore, String clientId, String clientSecret);
  }

  /**
   * Converts a configured secret key string into a validated SecretKey object
   * that can be used to sign tokens for our chosen secret key algorithm.
   *
   * @param secretKey raw text secret key
   * @return validated key object created from the input
   * @throws CryptoException if secret key is not compatible with the secret key algorithm
   */
  public static SecretKey getValidatedSecretKey(String secretKey) throws CryptoException {
    SecretKey key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
    if (!key.getAlgorithm().equals(SECRET_KEY_ALGORITHM.getJcaName())) {
      throw new CryptoException("Signing key '" + secretKey + "' is not compatible with " + SECRET_KEY_ALGORITHM.getJcaName());
    }
    return key;
  }

  public static KeyPair getKeyPair(String seed) throws CryptoException {
    if (seed == null || seed.length() < MINIMUM_SEED_LENGTH) {
      throw new CryptoException("Asynchronous key pair generation seed must be present and greater than " + MINIMUM_SEED_LENGTH + " characters");
    }
    SecureRandom random = new SecureRandom(seed.getBytes(StandardCharsets.UTF_8));
    return EllipticCurveProvider.generateKeyPair(ASYMMETRIC_KEY_ALGORITHM, random);
  }

  private static String createJwtFromJsonHmac(JsonObject tokenJson, SigningKeyStore keyStore, String clientId, String clientSecret) {
    Key key = keyStore.getSecretKey(clientId, clientSecret);
    log("Will create JWT using HMAC from the following token body: " + prettyPrintJson(tokenJson));
    String jwt = Jwts.builder()
        .setPayload(tokenJson.toString())
        .signWith(key)
        .compact();
    log("JWT created: " + jwt);
    return jwt;
  }

  private static String createJwtFromJsonEcdsa(JsonObject tokenJson, SigningKeyStore keyStore, String clientId, String clientSecret) {
    PrivateKey privateKey = keyStore.getAsyncKeys().getPrivate();
    log("Will create JWT using ECDSA from the following token body: " + prettyPrintJson(tokenJson));
    String jwt = Jwts.builder()
        .setPayload(tokenJson.toString())
        .signWith(privateKey)
        .compact();
    log("JWT created: " + jwt);
    return jwt;
  }

  private static void log(String message) {
    LogManager.getLogger(Signatures.class).debug(message);
  }

  private static String prettyPrintJson(JsonStructure json) {
    Map<String, Boolean> config = new HashMap<>();
    config.put(JsonGenerator.PRETTY_PRINTING, true);
    StringWriter writer = new StringWriter();
    try (JsonWriter jsonWriter = Json.createWriterFactory(config).createWriter(writer)) {
      jsonWriter.write(json);
    }
    return writer.toString();
  }

  public static JsonObject getJwksContent(SigningKeyStore keyStore) {

    // get the public key and be able to represent it as base64 or as xy coordinates
    ECPublicKey publicKey = (ECPublicKey)keyStore.getAsyncKeys().getPublic();
    ECPublicKeyRepresentation publicKeyRep = new ECPublicKeyRepresentation(publicKey);
    ECCoordinateStrings publicKeyCoords = publicKeyRep.getCoordinates();

    return Json.createObjectBuilder()
      .add("keys", Json.createArrayBuilder()
        .add(Json.createObjectBuilder()
          .add("kid", "0")
          .add("use", "sig")
          .add("fmt", keyStore.getSecretKeyFormat())
          .add("kty", "oct")
          .add("alg", Signatures.SECRET_KEY_ALGORITHM.getValue())
          .add("k", "<your_client_secret>")
          .build())
        .add(Json.createObjectBuilder()
          .add("kid", "1")
          .add("use", "sig")
          .add("fmt", publicKey.getFormat())
          .add("kty", "EC")
          .add("alg", Signatures.ASYMMETRIC_KEY_ALGORITHM.getValue())
          .add("crv","P-521")
          .add("x", publicKeyCoords.getX())
          .add("y", publicKeyCoords.getY())
          // Note: some clients may find it easier to use the base-64 encoded
          //       key vs coordinates, so including here as an extra property
          .add("k", publicKeyRep.getBase64String())
          .build())
        .build())
      .build();
  }

}
