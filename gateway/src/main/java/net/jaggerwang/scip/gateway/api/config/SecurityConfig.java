package net.jaggerwang.scip.gateway.api.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.HttpStatusServerEntryPoint;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(csrf -> csrf.disable())
                // TODO: This config will disable oauth2 login page at '/login'.
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        .authenticationEntryPoint(new HttpStatusServerEntryPoint(
                                HttpStatus.UNAUTHORIZED))
                )
                .authorizeExchange(authorizeExchange -> authorizeExchange
                        .pathMatchers("/favicon.ico", "/csrf", "/vendor/**", "/webjars/**",
                                "/*/actuator/**", "/", "/graphql", "/login", "/logout",
                                "/auth/**", "/hydra/**", "/user/register", "/files/**").permitAll()
                        .pathMatchers("/user/**").hasAuthority("SCOPE_user")
                        .pathMatchers("/post/**").hasAuthority("SCOPE_post")
                        .pathMatchers("/file/**").hasAuthority("SCOPE_file")
                        .pathMatchers("/stat/**").hasAuthority("SCOPE_stat")
                        .anyExchange().authenticated())
                .oauth2ResourceServer(oauth2ResourceServer -> oauth2ResourceServer.jwt())
                .oauth2Client(oauth2Client -> {})
                .oauth2Login(oauth2Login -> {})
                .build();
    }
}
