package org.sid.web;

import org.sid.entities.AppUser;
import org.sid.service.AccountService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController // rest dédié pour l'enregistrement
public class UserRestController {

    @Autowired
    private AccountService accountService;

    @PostMapping("/register")
    public AppUser register(@RequestBody RegisterForm userForm){
        if (!userForm.getPassword().equals(userForm.getRepassword()))
            throw  new RuntimeException("You must confirm your password");
        AppUser user = accountService.findUserByUsername(userForm.getUsername());
        if (user!= null)
            throw  new RuntimeException("this user already exists");
        AppUser appUser = new AppUser();
        appUser.setUsername(userForm.getUsername());
        appUser.setPassword(userForm.getPassword());

        accountService.saveUser(appUser);
        accountService.addRoleToUser(userForm.getUsername(), "USER");// on suppose l enregistrement que pour les profils USER
        return appUser;
    }
}
