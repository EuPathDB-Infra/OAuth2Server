package org.gusdb.oauth2.client;

import jakarta.ws.rs.core.Response.Status.Family;
import jakarta.ws.rs.core.Response.StatusType;

public enum HttpStatus implements StatusType {

  UNPROCESSABLE_CONTENT(422, Family.CLIENT_ERROR, "Unprocessable Content");

  private final int _statusCode;
  private final Family _family;
  private final String _reasonPhrase;

  private HttpStatus(int statusCode, Family family, String reasonPhrase) {
    _statusCode = statusCode;
    _family = family;
    _reasonPhrase = reasonPhrase;
  }

  @Override
  public int getStatusCode() {
    return _statusCode;
  }

  @Override
  public Family getFamily() {
    return _family;
  }

  @Override
  public String getReasonPhrase() {
    return _reasonPhrase;
  }

}
