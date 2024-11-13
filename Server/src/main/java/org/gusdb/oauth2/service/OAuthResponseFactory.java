package org.gusdb.oauth2.service;

import java.util.Collections;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.ResponseBuilder;

import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.gusdb.oauth2.client.UnacceptableRequestReason;

public class OAuthResponseFactory {

  private static ResponseBuilder NOT_ACCEPTABLE_RESPONSE = Response.notAcceptable(Collections.emptyList());

  public Response buildInvalidGrantTypeResponse() {
    return getNotAcceptableResponse(UnacceptableRequestReason.UNSUPPORTED_GRANT_TYPE);
  }

  public Response buildInvalidUserPassResponse() {
    return getNotAcceptableResponse(UnacceptableRequestReason.INVALID_USERNAME_PASSWORD);
  }

  public Response buildInvalidClientResponse() {
    return getNotAcceptableResponse(UnacceptableRequestReason.INVALID_CLIENT);
  }

  public Response buildBadAuthCodeResponse() {
    return getNotAcceptableResponse(UnacceptableRequestReason.INVALID_CLIENT);
  }

  public Response buildBadResponseTypeResponse() {
    return getNotAcceptableResponse(UnacceptableRequestReason.UNSUPPORTED_RESPONSE_TYPE);
  }

  public Response buildBadRedirectUrlResponse() {
    return getNotAcceptableResponse(UnacceptableRequestReason.INVALID_REDIRECT_URI);
  }

  public Response buildInvalidRequestResponse(OAuthProblemException e) {
    return NOT_ACCEPTABLE_RESPONSE.entity(e.getMessage()).build();
  }

  private static Response getNotAcceptableResponse(UnacceptableRequestReason reason) {
    return NOT_ACCEPTABLE_RESPONSE.entity(reason.name()).build();
  }

  public Response buildServerErrorResponse() {
    return Response.serverError().build();
  }

}
