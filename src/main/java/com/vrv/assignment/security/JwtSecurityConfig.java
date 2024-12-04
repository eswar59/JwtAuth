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
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
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
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.UUID;

@Configuration
public class JwtSecurityConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception{

        // authorizing all requests
//        http.authorizeHttpRequests(
//                auth -> {
//                    auth.anyRequest().authenticated();
//                });
//
//        // removing sessions
//        http.sessionManagement(
//                session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//        );
//
////        //make login basic as it is api
//        http.httpBasic();
//
//
        //remove csrf
        http.csrf( csrf -> csrf.disable() );
//
//        //adding frames so that we can use h2 database
//        http.headers().frameOptions().sameOrigin();
//
//        //adding oauth2 resource server to authorize jwts
//        http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);

        return http.build();
    }


//    @Bean
//    public DataSource dataSource(){
//        return new EmbeddedDatabaseBuilder()
//                .setType(EmbeddedDatabaseType.H2)
//                .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
//                .build();
//    }

    // adding users to be stored in db
    // here we will take datasource as arguement
//    @Bean
//    public UserDetailsService userDetailsService(DataSource dataSource){
//
//        var user1 = User.withUsername("eswar")
//                //.password("{noop}secret")
//                .password("secret")
//                .passwordEncoder( str -> passwordEncoder().encode(str))
//                //      ^                       ^
//                // Method to create user,    bcrypt encoder defined below as bean
//                .roles("USER")
//                .build();
//
//        var user2 = User.withUsername("admin")
//                .password("secret")
//                .passwordEncoder( str -> passwordEncoder().encode(str))
//                .roles("ADMIN")
//                .build();
//
//        var jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
//
//        jdbcUserDetailsManager.createUser(user1);
//        jdbcUserDetailsManager.createUser(user2);
//
//        return jdbcUserDetailsManager;
//    }

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


