package net.jaggerwang.scip.gateway.adapter.graphql.datafetcher;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.jaggerwang.scip.common.usecase.port.service.async.FileAsyncService;
import net.jaggerwang.scip.common.usecase.port.service.async.PostAsyncService;
import net.jaggerwang.scip.common.usecase.port.service.async.StatAsyncService;
import net.jaggerwang.scip.common.usecase.port.service.async.UserAsyncService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import reactor.core.publisher.Mono;


abstract public class AbstractDataFetcher {
    @Autowired
    protected ObjectMapper objectMapper;

    @Autowired
    protected UserAsyncService userAsyncService;

    @Autowired
    protected PostAsyncService postAsyncService;

    @Autowired
    protected FileAsyncService fileAsyncService;

    @Autowired
    protected StatAsyncService statAsyncService;

    protected Mono<Long> loggedUserId() {
        return ReactiveSecurityContextHolder.getContext()
                .flatMap(securityContext -> {
                    var auth = securityContext.getAuthentication();
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
