package net.jaggerwang.scip.gateway.adapter.controller;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import reactor.core.publisher.Mono;

abstract public class AbstractController {
    protected Mono<Long> loggedUserId() {
        return ReactiveSecurityContextHolder.getContext()
                .flatMap(context -> {
                    var auth = context.getAuthentication();
                    if (auth == null || auth instanceof AnonymousAuthenticationToken ||
                            !auth.isAuthenticated()) {
                        return Mono.empty();
                    }

                    var principal = auth.getPrincipal();
                    if (principal instanceof OAuth2User) {
                        var oAuth2User = (OAuth2User) auth.getPrincipal();
                        return Mono.just(Long.parseLong(oAuth2User.getName()));
                    } else if (principal instanceof Jwt) {
                        var jwt = (Jwt) auth.getPrincipal();
                        return Mono.just(Long.parseLong(jwt.getClaimAsString("sub")));
                    } else {
                        return Mono.empty();
                    }
                });
    }
}
