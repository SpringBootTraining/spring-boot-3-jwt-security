package com.alibou.security.entities.enums;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import static com.alibou.security.entities.enums.Permission.*;

@Getter
@RequiredArgsConstructor
public enum Role {

  USER(Collections.emptySet()),
  ADMIN(
          Set.of(
                  ADMIN_READ,
                  ADMIN_UPDATE,
                  ADMIN_DELETE,
                  ADMIN_CREATE,
                  MANAGER_READ,
                  MANAGER_UPDATE,
                  MANAGER_DELETE,
                  MANAGER_CREATE
          )
  ),
  MANAGER(
          Set.of(
                  MANAGER_READ,
                  MANAGER_UPDATE,
                  MANAGER_DELETE,
                  MANAGER_CREATE
          )
  );

  private final Set<Permission> permissions;

  /**
   * Retrieves a list of authorities for the current user.
   * It's a must to make this method return type one of the implementation classes that implements the GrantedAuthority interface
   * <p>
   * This method retrieves a list of authorities for the current user. These authorities are derived from the user's permissions
   * and the role associated with the user's name. The permissions are obtained by calling the getPermissions method, which
   * returns a list of Permission objects. Each Permission object is mapped to a SimpleGrantedAuthority object by extracting
   * the permission string via the getPermission method. These SimpleGrantedAuthority objects are then collected into a list.
   * Additionally, a SimpleGrantedAuthority object representing the user's role (prefixed with "ROLE_") is also added to the list.
   *
   * @return a list of SimpleGrantedAuthority objects representing the authorities of the current user
   */
  public List<SimpleGrantedAuthority> getAuthorities() {
    List<SimpleGrantedAuthority> authorities = getPermissions()
            .stream()
            .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
            .collect(Collectors.toList());
    authorities.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
    return authorities;
  }
}
