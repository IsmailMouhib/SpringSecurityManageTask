package org.sid.service;

import org.sid.entities.AppUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;

@Service
public class UserDetailServiceImpl implements UserDetailsService {

    @Autowired
    private AccountService accountService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        AppUser user = accountService.findUserByUsername(username);
        if (user == null) throw new UsernameNotFoundException(username);
        // recuperer les roles pour les passer dans l objet user retourner
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        // pqrceaue on a eager on recuperer les roles depuis user
        user.getAppRoles().forEach(appRole -> authorities.add(new SimpleGrantedAuthority(appRole.getRoleName())));
        return new User(user.getUsername(), user.getPassword(), authorities);
    }
}
