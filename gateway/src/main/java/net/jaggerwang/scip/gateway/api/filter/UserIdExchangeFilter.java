package net.jaggerwang.scip.gateway.api.filter;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import reactor.core.publisher.Mono;

@Component
public class UserIdExchangeFilter implements ExchangeFilterFunction {
    @Override
    public Mono<ClientResponse> filter(ClientRequest clientRequest,
                                       ExchangeFunction exchangeFunction) {
        return ReactiveSecurityContextHolder.getContext()
                .flatMap(securityContext -> {
                    var auth = securityContext.getAuthentication();
                    if (auth == null || auth instanceof AnonymousAuthenticationToken ||
                            !auth.isAuthenticated()) {
                        return exchangeFunction.exchange(clientRequest);
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
                        return exchangeFunction.exchange(clientRequest);
                    }
                    return exchangeFunction.exchange(ClientRequest.from(clientRequest)
                            .headers(headers -> headers
                                    .set("X-User-Id", userId))
                            .build());
                });
    }
}
