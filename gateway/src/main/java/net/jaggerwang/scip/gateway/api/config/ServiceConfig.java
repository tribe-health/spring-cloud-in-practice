package net.jaggerwang.scip.gateway.api.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.timelimiter.TimeLimiterConfig;
import net.jaggerwang.scip.common.adapter.service.async.*;
import net.jaggerwang.scip.common.api.filter.HeadersRelayFilter;
import net.jaggerwang.scip.common.usecase.port.service.async.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.circuitbreaker.resilience4j.ReactiveResilience4JCircuitBreakerFactory;
import org.springframework.cloud.circuitbreaker.resilience4j.Resilience4JConfigBuilder;
import org.springframework.cloud.client.circuitbreaker.Customizer;
import org.springframework.cloud.client.circuitbreaker.ReactiveCircuitBreakerFactory;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Duration;
import java.util.Set;

@Configuration(proxyBeanMethods = false)
public class ServiceConfig {
    @Bean
    public Customizer<ReactiveResilience4JCircuitBreakerFactory> cbFactoryCustomizer() {
        return factory -> factory.configureDefault(id -> {
            var timeout = Duration.ofSeconds(5);
            if (id.equals("fast")) {
                timeout = Duration.ofSeconds(2);
            } else if (id.equals("slow")) {
                timeout = Duration.ofSeconds(10);
            }

            return new Resilience4JConfigBuilder(id)
                    .circuitBreakerConfig(CircuitBreakerConfig.ofDefaults())
                    .timeLimiterConfig(TimeLimiterConfig.custom()
                            .timeoutDuration(timeout)
                            .build())
                    .build();
        });
    }

    @LoadBalanced
    @Bean
    public WebClient.Builder webClientBuilder() {
        var headersRelayFilter = new HeadersRelayFilter(Set.of(HttpHeaders.AUTHORIZATION,
                HttpHeaders.COOKIE));
        return WebClient.builder().filter(headersRelayFilter);
    }

    @Bean
    public UserAsyncService userAsyncService(WebClient.Builder builder,
                                             ReactiveCircuitBreakerFactory cbFactory,
                                             ObjectMapper objectMapper) {
        var webClient = builder.baseUrl("http://spring-cloud-in-practice-user").build();
        return new UserAsyncServiceImpl(webClient, cbFactory, objectMapper);
    }

    @Bean
    public PostAsyncService postAsyncService(WebClient.Builder builder,
                                             ReactiveCircuitBreakerFactory cbFactory,
                                             ObjectMapper objectMapper) {
        var webClient = builder.baseUrl("http://spring-cloud-in-practice-post").build();
        return new PostAsyncServiceImpl(webClient, cbFactory, objectMapper);
    }

    @Bean
    public FileAsyncService fileAsyncService(WebClient.Builder builder,
                                             ReactiveCircuitBreakerFactory cbFactory,
                                             ObjectMapper objectMapper) {
        var webClient = builder.baseUrl("http://spring-cloud-in-practice-file").build();
        return new FileAsyncServiceImpl(webClient, cbFactory, objectMapper);
    }

    @Bean
    public StatAsyncService statAsyncService(WebClient.Builder builder,
                                             ReactiveCircuitBreakerFactory cbFactory,
                                             ObjectMapper objectMapper) {
        var webClient = builder.baseUrl("http://spring-cloud-in-practice-stat").build();
        return new StatAsyncServiceImpl(webClient, cbFactory, objectMapper);
    }

    @Bean
    public HydraAsyncService hydraAsyncService(@Value("${service.hydra.admin-url}") String baseUrl,
                                               ReactiveCircuitBreakerFactory cbFactory) {
        var webClient = WebClient.builder().baseUrl(baseUrl).build();
        return new HydraAsyncServiceImpl(webClient, cbFactory);
    }
}
