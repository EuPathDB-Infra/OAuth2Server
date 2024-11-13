package org.gusdb.oauth2.server;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Application listener closes resources on the client-provided Authenticator
 * class.  This listener should be included in web.xml if your Authenticator
 * opens resources during its init() method that must be closed before the
 * object is finalized.  Including this listener ensures those resources are
 * closed during web app shut down; if your Authenticator does not open
 * resources, you need not register this listener in web.xml.
 * 
 * Edit: This listener is also now responsible for shutting down the token
 * expirer thread.  If your application reports a possible memory leak on
 * webapp undeploy, you should include this listener in your app's web.xml.
 * 
 * @author ryan
 */
public class ApplicationListener implements ServletContextListener {

  private static final Logger LOG = LogManager.getLogger(ApplicationListener.class);

  @Override
  public void contextInitialized(ServletContextEvent event) {
    LOG.info("Starting up OAuth Server webapp");
    // nothing to do here
  }

  @Override
  public void contextDestroyed(ServletContextEvent event) {
    LOG.info("Shutting down OAuth Server webapp");
    OAuthServlet.getAuthenticator(event.getServletContext()).close();
    TokenExpirerThread.shutdown();
  }

}
