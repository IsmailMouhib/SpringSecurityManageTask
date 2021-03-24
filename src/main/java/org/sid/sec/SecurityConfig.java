package org.sid.sec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {


    @Autowired
    @Qualifier("userDetailServiceImpl")
    private UserDetailsService userDetailsService;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        /*auth.inMemoryAuthentication()
                .withUser("admin").password("{noop}1234").roles("ADMIN","USER")
        .and().withUser("user").password("{noop}1111").roles("USER");
         */
        /*auth.jdbcAuthentication().usersByUsernameQuery("")
                .authoritiesByUsernameQuery("").passwordEncoder() */
        // on delegue le traitement à une couche de service (interface de spring security UserDetailsService)
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable(); // spring génére par defaut CSRF hidden dans l input deu formulaire le synchronize tokencontre les attaques CROSS SITE FORGERY (on le desactive si on utlise JWT)
        http.headers().frameOptions().disable(); // for deblock H2-Console is not showing in browser

        //desactiver le mode session utilise par spring security car par défaut spring utilise l'authenticatin via les sessions
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS); // don't create session, on va passer d'un passage par referenece qui est session au passage par valeur jwt car tt ce trouve dans ce dernier

        //http.formLogin(); // formulaire par defaut d authentication de spring

        // le formulaire d authentification ne cessite pas une authority
        http.authorizeRequests().antMatchers("/login/**","/register/**","/h2-console/**").permitAll();
        http.authorizeRequests().antMatchers(HttpMethod.POST, "/tasks/**").hasAuthority("ADMIN");// seulement l ADMIN QUI PEUT AJOUTER des taches

        // toutes les requetes necessites une authentification
        http.authorizeRequests().anyRequest().authenticated();

        // Ajouter le filter d authentication
        http.addFilter(new JWTAuthentificationFilter(authenticationManager()));

        // Ajouter le filter d authorisation ==  ce filtre s execute pour chaque requete
        http.addFilterBefore(new JWTAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);
    }

}
