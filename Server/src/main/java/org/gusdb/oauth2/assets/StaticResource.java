package org.gusdb.oauth2.assets;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import jakarta.ws.rs.core.StreamingOutput;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class StaticResource {

  private static final Logger LOG = LogManager.getLogger(StaticResource.class);

  public static final String RESOURCE_PREFIX = "assets/";

  private static final AtomicInteger RESOURCE_COUNT = new AtomicInteger(0);

  private static final List<ResponseType> VALID_TYPES =
      Arrays.asList(new ResponseType[] {
          ResponseType.html,
          ResponseType.css,
          ResponseType.javascript,
          ResponseType.jpeg,
          ResponseType.gif,
          ResponseType.png,
          ResponseType.json
      });

  private final String _name;
  private final int _ordinal;
  private final boolean _isValid;
  private final ResponseType _responseType; // null if name is bad type
  private final URL _url;                   // null if name is bad type or file cannot be found

  public StaticResource(String name) {
    _name = name;
    _ordinal = RESOURCE_COUNT.incrementAndGet();
    boolean isValid = false;
    ResponseType responseType = null;
    URL url = null;
    try {
      responseType = ResponseType.resolveType(Paths.get(_name));
      if (VALID_TYPES.contains(responseType)) {
        log("Is a valid response type");
        // make sure we can actually access this resource
        url = Thread.currentThread().getContextClassLoader().getResource(RESOURCE_PREFIX + _name);
        log("Found? " + (url != null));
        isValid = (url != null);
      }
      else {
        log("Not a valid response type. Request marked invalid.");
      }
    }
    catch (IllegalArgumentException e) {
      log("Not a valid request. " + e.getMessage());
    }
    _isValid = isValid;
    _responseType = responseType;
    _url = url;
    log("StaticResource object created, isValid="+ _isValid);
  }

  private void log(String s) {
    LOG.debug(_ordinal + " (" + _name + "): " + s);
  }

  public boolean isValid() {
    return _isValid;
  }

  public Optional<URL> getResourceUrl() {
    return Optional.ofNullable(_url);
  }

  public Optional<StreamingOutput> getStreamingOutput() {
    return !_isValid ? Optional.empty() : Optional.of(out -> {
      log("Opening resource stream");
      try (InputStream in = _url.openStream()) {
        log("Starting data transfer");
        transferStream(out, in);
        log("Completed data transfer");
      }
      log("Resource stream closed");
    });
  }

  public String getMimeType() {
    return (_isValid ?
      _responseType.getMimeType() :
      ResponseType.text.getMimeType());
  }

  /**
   * NOTE: this is a copy of the transferStream method in FgpUtil (sans logging)
   * 
   * Transfers data from input stream to the output stream until no more data
   * is available, then closes input stream (but not output stream).
   * 
   * @param outputStream output stream data is written to
   * @param inputStream input stream data is read from
   * @throws IOException if problem reading/writing data occurs
   */
  public static void transferStream(OutputStream outputStream, InputStream inputStream)
      throws IOException {
    try {
      byte[] buffer = new byte[10240]; // send 10kb at a time
      int bytesRead = inputStream.read(buffer);
      while (bytesRead != -1) {
        outputStream.write(buffer, 0, bytesRead);
        bytesRead = inputStream.read(buffer);
      }
      outputStream.flush();
    }
    finally {
      // only close input stream; container will close output stream
      inputStream.close();
    }
  }
}
