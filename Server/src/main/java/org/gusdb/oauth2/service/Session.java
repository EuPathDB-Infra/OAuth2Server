package org.gusdb.oauth2.service;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import jakarta.servlet.http.HttpSession;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.gusdb.oauth2.service.token.TokenStore;
import org.gusdb.oauth2.service.util.AuthzRequest;

public class Session {

  private static final Logger LOG = LogManager.getLogger(Session.class);

  private static final String SESSION_LOGINNAME_KEY = "loginName";
  private static final String SESSION_USERID_KEY = "userId";
  private static final String SESSION_FORM_ID_MAP_KEY = "formIdMap";

  private final HttpSession _session;

  public Session(HttpSession session) {
    _session = session;
    synchronized(session) {
      if (getFormIdMap() == null) {
        _session.setAttribute(SESSION_FORM_ID_MAP_KEY, new HashMap<String, AuthzRequest>());
      }
    }
  }

  public boolean isAuthenticated() {
    return getLoginName() != null;
  }

  public String getLoginName() {
    return (String)_session.getAttribute(SESSION_LOGINNAME_KEY);
  }

  public void setLoginName(String loginName) {
    _session.setAttribute(SESSION_LOGINNAME_KEY, loginName);
  }

  public String getUserId() {
    return (String)_session.getAttribute(SESSION_USERID_KEY);
  }

  public void setUserId(String userId) {
    _session.setAttribute(SESSION_USERID_KEY, userId);
  }

  public void setMaxInactiveIntervalSecs(int maxInactiveIntervalSecs) {
    _session.setMaxInactiveInterval(maxInactiveIntervalSecs);
  }

  public AuthzRequest getOriginalRequest(String formId) {
    return getFormIdMap().get(formId);
  }

  public AuthzRequest clearFormId(String formId) {
    return getFormIdMap().remove(formId);
  }

  public boolean isFormId(String formId) {
    return getFormIdMap().containsKey(formId);
  }

  public String generateFormId(AuthzRequest authRequest) {
    String nextFormId = UUID.randomUUID().toString();
    LOG.debug("Generated formId [" + nextFormId + "] to reference AuthzRequest");
    getFormIdMap().put(nextFormId, authRequest);
    return nextFormId;
  }

  public Set<String> getFormIds() {
    return getFormIdMap().keySet();
  }

  @SuppressWarnings("unchecked")
  private Map<String, AuthzRequest> getFormIdMap() {
    return (Map<String, AuthzRequest>)_session.getAttribute(SESSION_FORM_ID_MAP_KEY);
  }

  public void invalidate() {
    String username = getLoginName();
    if (username != null) {
      TokenStore.clearObjectsForUser(username);
    }
    _session.invalidate();
  }

}
