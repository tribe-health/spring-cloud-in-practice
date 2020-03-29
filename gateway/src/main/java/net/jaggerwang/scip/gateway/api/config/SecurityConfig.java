package net.jaggerwang.scip.gateway.api.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.jaggerwang.scip.common.usecase.port.service.dto.RootDto;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.WebSessionServerOAuth2AuthorizedClientRepository;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.io.IOException;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {
    private ObjectMapper objectMapper;

    public SecurityConfig(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    private Mono<Void> responseJson(ServerWebExchange exchange, HttpStatus status, RootDto data) {
        var response = exchange.getResponse();
        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        var body = new byte[0];
        try {
            body = objectMapper.writeValueAsBytes(data);
        } catch (IOException e) {
        }
        return response.writeWith(Flux.just(response.bufferFactory().wrap(body)));
    }

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(csrf -> csrf.disable())
                // TODO: It will cause '/login' page not found.
//                .exceptionHandling(exceptionHandling -> exceptionHandling
//                        .authenticationEntryPoint((exchange, exception) ->
//                                responseJson(exchange, HttpStatus.UNAUTHORIZED,
//                                        new RootDto("unauthenticated", "未认证")))
//                        .accessDeniedHandler((exchange, accessDeniedException) ->
//                                responseJson(exchange, HttpStatus.FORBIDDEN,
//                                        new RootDto("unauthorized", "未授权")))
//                )
                .authorizeExchange(authorizeExchange -> authorizeExchange
                        .pathMatchers("/favicon.ico", "/csrf", "/vendor/**", "/webjars/**",
                                "/*/actuator/**", "/", "/graphql", "/login", "/logout",
                                "/auth/login", "/auth/logout", "/auth/logged",
                                "/user/register", "/files/**", "/hydra/**").permitAll()
                        .pathMatchers("/user/**").hasAuthority("SCOPE_user")
                        .pathMatchers("/post/**").hasAuthority("SCOPE_post")
                        .pathMatchers("/file/**").hasAuthority("SCOPE_file")
                        .pathMatchers("/stat/**").hasAuthority("SCOPE_stat")
                        .anyExchange().authenticated())
                .oauth2Client(oauth2Client -> {})
                .oauth2Login(oauth2Login -> {})
                .oauth2ResourceServer(oauth2ResourceServer -> oauth2ResourceServer.jwt())
                .build();
    }

    @Bean
    ServerOAuth2AuthorizedClientRepository authorizedClientRepository() {
        return new WebSessionServerOAuth2AuthorizedClientRepository();
    }
}
