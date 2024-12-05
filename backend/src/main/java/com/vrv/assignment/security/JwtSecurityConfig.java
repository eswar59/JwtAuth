package com.vrv.assignment.security;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.UUID;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class JwtSecurityConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception{

        // authorizing all requests
        http.authorizeHttpRequests(
                auth ->
                    auth.requestMatchers("/createUser", "/createToken")
                            .permitAll()
                            .requestMatchers(HttpMethod.OPTIONS,"/**")
                            .permitAll()
                            .requestMatchers("/admin").hasAuthority("SCOPE_ADMIN")
                            .requestMatchers("/moderator").hasAnyAuthority("SCOPE_MODERATOR", "SCOPE_ADMIN")
                            .anyRequest()
                            .authenticated()
                );

        // removing sessions
        http.sessionManagement(
                session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        );


        http.httpBasic();

        http.csrf().disable();

        http.exceptionHandling(
                (ex) ->
                        ex.authenticationEntryPoint(
                                        new BearerTokenAuthenticationEntryPoint())
                                .accessDeniedHandler(
                                        new BearerTokenAccessDeniedHandler()));

        //adding oauth2 resource server to authorize jwts
        http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);

        return http.build();
    }
    @Bean
    public AuthenticationManager authenticationManager(
            UserDetailsService userDetailsService) {
        var authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        authenticationProvider.setUserDetailsService(userDetailsService);
        return new ProviderManager(authenticationProvider);
    }

    //encoding password and then storing in the database using bcryptpassword encoder
    @Bean
    public BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    //------------------------------------------------------------------------
    // above for user details, below jwt oauth also for jwt configure the above
    // filter chain also

    // step 1 generate a key pair
    @Bean
    public KeyPair keyPairGeneration() {
        try{
            var keypairgenerator = KeyPairGenerator.getInstance("RSA");
            keypairgenerator.initialize(2048);
            return keypairgenerator.generateKeyPair();
        }catch(Exception ex){
            throw new RuntimeException(ex);
        }
    }

    // step 2 create RSA key object using the keypair
    @Bean
    public RSAKey rsaKeyGeneration(KeyPair keyPairGeneration){
        return new com.nimbusds.jose.jwk.RSAKey
                .Builder((RSAPublicKey) keyPairGeneration.getPublic())
                .privateKey(keyPairGeneration.getPrivate())
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    // step 3 create a JWKSource and give our key to it source stores keys
    @Bean
    public JWKSource<SecurityContext> jwkSource(RSAKey rsaKeyGeneration){
        var jwkSet = new JWKSet(rsaKeyGeneration);
        return ((jwkSelector, securityContext) -> jwkSelector.select(jwkSet));

        //BELOW CODE IN LAMBDAFUNCTIONS ABOVE
//        var jwkSource = new JWKSource(){
//            @Override
//            public List get(JWKSelector jwkSelector, SecurityContext securityContext) throws KeySourceException {
//                return jwkSelector.select(jwkSet);
//            }
//        }

    }

    // step 4 creating the decoder bean to verify tokens
    @Bean
    public JwtDecoder jwtDecoder(RSAKey rsaKey) throws JOSEException {
        return NimbusJwtDecoder
                .withPublicKey(rsaKey.toRSAPublicKey())
                .build();
    }

    // step 5 creating encoder to encode the jwt
    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource){
        return new NimbusJwtEncoder(jwkSource);
    }

}


