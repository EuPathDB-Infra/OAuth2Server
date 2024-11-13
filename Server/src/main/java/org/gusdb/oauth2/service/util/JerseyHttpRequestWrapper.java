package org.gusdb.oauth2.service.util;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.ws.rs.core.MultivaluedMap;

public class JerseyHttpRequestWrapper extends HttpServletRequestWrapper {

  private final MultivaluedMap<String, String> _formParams;

  public JerseyHttpRequestWrapper(HttpServletRequest request, MultivaluedMap<String, String> formParams) {
    super(request);
    _formParams = formParams;
  }

  @Override
  public Enumeration<String> getParameterNames() {
    return new ListEnumeration<String>(new ArrayList<String>(_formParams.keySet()));
  }

  @Override
  public String getParameter(String name) {
    return _formParams.getFirst(name);
  }

  @Override
  public String[] getParameterValues(String name) {
    return _formParams.get(name).toArray(new String[]{});
  }

  @Override
  public Map<String, String[]> getParameterMap() {
    Map<String, String[]> map = new HashMap<>();
    for (String key : _formParams.keySet()) {
      map.put(key, getParameterValues(key));
    }
    return map;
  }

  public static class ListEnumeration<T> implements Enumeration<T> {

    private final List<T> _elements;
    private int _currentIndex = 0;

    public ListEnumeration(List<T> elements) {
      _elements = elements;
    }

    @Override
    public boolean hasMoreElements() {
      return (_currentIndex < _elements.size());
    }

    @Override
    public T nextElement() throws NoSuchElementException {
      if (!hasMoreElements()) throw new NoSuchElementException();
      return _elements.get(_currentIndex++);
    }
  }
}
