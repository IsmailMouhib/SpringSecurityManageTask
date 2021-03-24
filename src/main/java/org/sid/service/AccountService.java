package org.sid.service;

import org.sid.entities.AppRole;
import org.sid.entities.AppUser;

public interface AccountService {

    AppUser saveUser(AppUser appUser);
    AppRole saveRole(AppRole appRole);
    void addRoleToUser(String userneme, String roleName);
    AppUser findUserByUsername(String name);
}
