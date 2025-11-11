package com.evoke.auth.security;

import com.evoke.auth.Constants;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    
    private final JwtProvider jwtProvider;
    
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getRequestURI();
        return path.startsWith("/h2-console");
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                  HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String jwt = getJwtFromRequest(request);
            
            if (StringUtils.hasText(jwt) && jwtProvider.validateToken(jwt)) {
                String username = jwtProvider.getUsernameFromToken(jwt);
                String authoritiesString = jwtProvider.getAuthoritiesFromToken(jwt);
                
                // Extract authorities from JWT instead of database lookup
                List<GrantedAuthority> authorities = Collections.emptyList();
                if (StringUtils.hasText(authoritiesString)) {
                    authorities = Arrays.stream(authoritiesString.split(","))
                        .map(String::trim)
                        .filter(StringUtils::hasText)
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());
                }
                
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(username, null, authorities);
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                
                SecurityContextHolder.getContext().setAuthentication(authentication);
                log.debug("Set authentication for user: {} with authorities: {}", username, authoritiesString);
            }
        } catch (Exception e) {
            log.error("Cannot set user authentication", e);
        }
        
        filterChain.doFilter(request, response);
    }
    
    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader(Constants.JWT_HEADER);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(Constants.JWT_TOKEN_PREFIX)) {
            return bearerToken.substring(Constants.JWT_TOKEN_PREFIX.length());
        }
        return null;
    }
}