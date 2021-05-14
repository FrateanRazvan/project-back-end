package ubb.postuniv.Project2021.security;

import com.google.common.collect.Sets;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

import static ubb.postuniv.Project2021.security.AplicationUserPermission.*;

public enum AplicationUserRole {
    USER(Sets.newHashSet()),
    ADMIN(Sets.newHashSet(PROJECT_READ, PROJECT_WRITE, USER_READ, USER_WRITE)),
    ADMINISTRATOR(Sets.newHashSet(PROJECT_READ, USER_READ));


    private final Set<AplicationUserPermission> permissions;

    AplicationUserRole(Set<AplicationUserPermission> permissions) {
        this.permissions = permissions;
    }

    public Set<AplicationUserPermission> getPermissions() {
        return permissions;
    }

    public Set<SimpleGrantedAuthority> getGrantedAuthorities(){
        Set<SimpleGrantedAuthority> permissions = getPermissions().stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
                .collect(Collectors.toSet());

        permissions.add(new SimpleGrantedAuthority("ROLE_" + this.name()));

        return permissions;
    }
}
