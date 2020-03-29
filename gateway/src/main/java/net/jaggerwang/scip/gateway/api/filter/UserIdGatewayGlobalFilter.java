package net.jaggerwang.scip.gateway.api.filter;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class UserIdGatewayGlobalFilter implements GlobalFilter {
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .flatMap(securityContext -> {
                    var auth = securityContext.getAuthentication();
                    if (auth == null || auth instanceof AnonymousAuthenticationToken ||
                            !auth.isAuthenticated()) {
                        return chain.filter(exchange);
                    }

                    String userId;
                    var principal = auth.getPrincipal();
                    if (principal instanceof OAuth2User) {
                        var oAuth2User = (OAuth2User) auth.getPrincipal();
                        userId = oAuth2User.getName();
                    } else if (principal instanceof Jwt) {
                        var jwt = (Jwt) auth.getPrincipal();
                        userId = jwt.getClaimAsString("sub");
                    } else {
                        return chain.filter(exchange);
                    }
                    return chain.filter(exchange.mutate()
                            .request(exchange.getRequest()
                                    .mutate()
                                    .headers(headers -> headers
                                            .set("X-User-Id", userId))
                                    .build())
                            .build());
                });
    }
}
