package net.jaggerwang.scip.gateway.adapter.controller;

import net.jaggerwang.scip.common.usecase.port.service.async.UserAsyncService;
import net.jaggerwang.scip.common.usecase.port.service.dto.RootDto;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/auth")
public class AuthController extends AbstractController {
    private UserAsyncService userAsyncService;

    public AuthController(UserAsyncService userAsyncService) {
        this.userAsyncService = userAsyncService;
    }

    @GetMapping("/logged")
    public Mono<RootDto> logged() {
        return loggedUserId()
                .flatMap(userId -> userAsyncService.info(userId))
                .map(user -> new RootDto().addDataEntry("user", user))
                .defaultIfEmpty(new RootDto().addDataEntry("user", null));
    }
}
