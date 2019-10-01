package org.sid.sec;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

public class JWTAuthorizationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // J autorise le client qu'il m envoie les entetes
        response.addHeader("Access-Control-Allow-origin", "*");
        response.addHeader("Access-Control-Allow-Headers", "Origin, Accept, X-Requested-With, Content-Type, Access-Control-Request-Method, " +
                "Access-Control-Request-Headers, Authorization");

        // J autorise à travers l exposition l utilisation des entetes
        response.addHeader("Access-Control-Expose-Headers","Access-Control-Allow-origin, Access-Control-Allow-Credentials, Authorization");

        String jwt = request.getHeader(SecurityConstants.HEADER_STRING);

        // la premiere methode envoyer l faut l autoriser dans la premiere connxion
        if (request.getMethod().equals("OPTIONS")){
            response.setStatus(HttpServletResponse.SC_OK);
        } else {
            if (jwt == null || !jwt.startsWith(SecurityConstants.TOKEN_PRIFIXE)) {
                filterChain.doFilter(request,response);
                return;
            }
            // signer le token à travers le parse
            Claims claims = Jwts.parser()
                    .setSigningKey(SecurityConstants.SECRET)
                    // supprimer le berear prefixe pour recuperer le jwt
                    .parseClaimsJws(jwt.replace(SecurityConstants.TOKEN_PRIFIXE,""))
                    .getBody();
            // charger le nom
            String username =claims.getSubject();
            // charger les roles ; un tableau clé valeur exp authority : ADMIN
            ArrayList<Map<String,String>> roles= (ArrayList<Map<String, String>>) claims.get("roles");
            Collection<GrantedAuthority> authorities = new ArrayList<>();
            // parcourir les roles et les tockes dans grantedAuthority
            roles.forEach(r -> authorities.add(new SimpleGrantedAuthority(r.get("authority"))));
            //passer les infos pour creer notre USER
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, null, authorities);
            // on informe spring security par l identite de l utilisateur
            // qui a envoye la requete afin que le charge dans le context spring
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            System.out.println("********** doFilterInternal *******************");
            System.out.println("JWT Authorezation filter = construire le jwt et l'envoyer au client");
            filterChain.doFilter(request,response);
        }
    }
}
