package org.sid.service;

import org.sid.entities.AppRole;
import org.sid.entities.AppUser;

public interface AccountService {

    public AppUser saveUser(AppUser appUser);
    public AppRole saveRole(AppRole appRole);
    public void addRoleToUser(String userneme, String roleName);
    public AppUser findUserByUsername(String name);
}
