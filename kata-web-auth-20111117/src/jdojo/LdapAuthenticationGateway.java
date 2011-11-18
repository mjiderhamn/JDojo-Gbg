package jdojo;

public interface LdapAuthenticationGateway {
  boolean credentialsAreValid(String userName, String password);
}
