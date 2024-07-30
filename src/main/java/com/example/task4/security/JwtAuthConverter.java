package com.example.task4.security;


import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
public class JwtAuthConverter implements ServerAuthenticationConverter {

    private final JwtUtil jwtUtil;

    public JwtAuthConverter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        HttpServletRequest request = (HttpServletRequest) exchange.getRequest();
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            String username = jwtUtil.extractUsername(token);
            if (username != null) {
                List<SimpleGrantedAuthority> authorities = jwtUtil.getAuthorities(token);
                return Mono.just(new UsernamePasswordAuthenticationToken(username, null, authorities));
            }
        }
        return Mono.empty();
    }
}
