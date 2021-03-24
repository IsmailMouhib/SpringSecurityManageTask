package org.sid.service;

import org.sid.dao.RoleRepository;
import org.sid.dao.UserRepository;
import org.sid.entities.AppRole;
import org.sid.entities.AppUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
// centraliser la gestion des users et roles
public class AccountServiceImpl implements AccountService {

    @Autowired
    BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Override
    public AppUser saveUser(AppUser appUser) {
        String hashPW = bCryptPasswordEncoder.encode(appUser.getPassword());
        appUser.setPassword(hashPW);
        return userRepository.save(appUser);
    }

    @Override
    public AppRole saveRole(AppRole appRole) {
        return roleRepository.save(appRole);
    }

    @Override
    public void addRoleToUser(String userneme, String roleName) {

        AppRole role = roleRepository.findByRoleName(roleName);
        AppUser user = userRepository.findByUsername(userneme);
        user.getAppRoles().add(role);
    }

    @Override
    public AppUser findUserByUsername(String name) {
        return userRepository.findByUsername(name);
    }
}
