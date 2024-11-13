package org.gusdb.oauth2.server;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.glassfish.jersey.servlet.ServletContainer;
import org.glassfish.jersey.servlet.ServletProperties;
import org.gusdb.oauth2.Authenticator;
import org.gusdb.oauth2.InitializationException;
import org.gusdb.oauth2.config.ApplicationConfig;
import org.gusdb.oauth2.service.ClientValidator;

public class OAuthServlet extends ServletContainer {

  private static final long serialVersionUID = 1L;
  
  private static final Logger LOG = LogManager.getLogger(OAuthServlet.class);

  private static final String CONFIG_FILE_PARAM_KEY = "oauth.config.file";
  private static final String OAUTH_CONFIG_KEY = "oauth.config";
  private static final String OAUTH_AUTHENTICATOR_KEY = "oauth.authenticator";

  public static ApplicationConfig getApplicationConfig(ServletContext context) {
    return (ApplicationConfig)context.getAttribute(OAUTH_CONFIG_KEY);
  }

  public static Authenticator getAuthenticator(ServletContext context) {
    return (Authenticator)context.getAttribute(OAUTH_AUTHENTICATOR_KEY);
  }

  public static ClientValidator getClientValidator(ServletContext servletContext) {
    ApplicationConfig config = getApplicationConfig(servletContext);
    return new ClientValidator(config.getAllowedClients(), config.validateDomains());
  }

  @Override
  public void init() throws ServletException {
    super.init();
    try {
      configureApplication();
    }
    catch (InitializationException e) {
      String message = "Failed to initialize OAuth server";
      LOG.error(message, e);
      throw new ServletException(message, e);
    }
  }

  private void configureApplication() throws InitializationException {
    String configFileName = getServletConfig().getInitParameter(CONFIG_FILE_PARAM_KEY);
    Path configFilePath = resolveConfigFilePath(configFileName);
    LOG.info("Initializing OAuth Server with config: " + configFileName);
    try {
      ServletContext context = getServletContext();
      ApplicationConfig config = ApplicationConfig.parseConfigFile(configFilePath);
      LOG.info("Configuration parsed successfully.");
      LOG.info("Will initialize Authenticator implementation: " + config.getAuthClassName());
      context.setAttribute(OAUTH_CONFIG_KEY, config);
      context.setAttribute(OAUTH_AUTHENTICATOR_KEY, getAuthenticator(config));
      LOG.info("Authenticator successfully initialized.");
      TokenExpirerThread.start(config);
      LOG.info("Ready to serve requests from " + config.getAllowedClients().size() + " unique clients.");
    }
    catch (InitializationException e) {
      throw e;
    }
    catch (Exception e) {
      throw new InitializationException("Unable to parse OAuth configuration file: " + configFileName, e);
    }
  }

  private Path resolveConfigFilePath(String configFileName) throws InitializationException {
    if (configFileName == null || configFileName.isEmpty()) {
      throw new InitializationException("Missing required servlet init parameter: '" + CONFIG_FILE_PARAM_KEY + "'");
    }
    Path configFilePath = Paths.get(configFileName);
    if (!configFilePath.isAbsolute()) {
      String searchPath = File.separator + configFilePath.toString();
      LOG.info("Trying to get real path of relative config file path: " + searchPath);
      String resolvedPath = getServletContext().getRealPath(searchPath);
      if (resolvedPath == null) {
        throw new InitializationException("Cannot realize relative config file path '" + configFileName +
            "'.  Does your servlet container explode your war file?");
      }
      configFilePath = Paths.get(resolvedPath);
    }
    if (!Files.isReadable(configFilePath)) {
      throw new InitializationException("Unable to read OAuth configuration file: " + configFileName +
          " (attempted full path: " + configFilePath.toAbsolutePath() + ")");
    }
    return configFilePath;
  }

  private static Authenticator getAuthenticator(ApplicationConfig config) throws InitializationException {
    String classMsg = "Specified authenticator class '" + config.getAuthClassName() + "'";
    try {
      @SuppressWarnings("unchecked")
      Class<? extends Authenticator> authClass = (Class<? extends Authenticator>)Class.forName(config.getAuthClassName());
      Authenticator authenticator = authClass.getConstructor().newInstance();
      authenticator.initialize(config.getAuthClassConfig());
      return authenticator;
    }
    catch (ClassCastException e) {
      throw new InitializationException(classMsg + " does not implement " + Authenticator.class.getName(), e);
    }
    catch (ClassNotFoundException e) {
      throw new InitializationException(classMsg + " cannot be found", e);
    }
    catch (IllegalAccessException e) {
      throw new InitializationException(classMsg + " must have a public no-arg constructor", e);
    }
    catch (InitializationException e) {
      throw e;
    }
    catch (Exception e) {
      throw new InitializationException(classMsg + " failed to initialize with provided configuration", e);
    }
  }

  @Override
  public String getInitParameter(String name) {
    if (name.equals(ServletProperties.JAXRS_APPLICATION_CLASS)) {
      return ServiceApplication.class.getName();
    }
    return super.getInitParameter(name);
  }
}
