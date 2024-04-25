package com.backend.security.config;


import com.backend.security.service.CustomUserDetailsService;
import com.backend.security.service.JwtService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final CustomUserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull  FilterChain filterChain) throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");
        String token;
        String userName;

        if (authHeader != null && authHeader.startsWith("Bearer")) {

            token = authHeader.substring(7);

            try {

                userName = this.jwtService.extractUsername(token);

                if(userName != null && SecurityContextHolder.getContext().getAuthentication() == null){
                    UserDetails userDetails = userDetailsService.loadUserByUsername(userName);

                    if(jwtService.validateToken(token, userDetails)){
                        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                        authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    }
                }

                filterChain.doFilter(request, response);

            } catch (IllegalArgumentException e) {
                sendErrorResponse(response, "---- Illegal Argument while fetching the username !!");
            } catch (ExpiredJwtException e) {
                sendErrorResponse(response, "---- Given jwt token is expired !!");
            } catch (MalformedJwtException e) {
                log.error("---- Some changed has done in token !! Invalid Token: ", e);
            } catch (Exception e) {
                log.error("---- Auth Filter Error: ", e);
            }


        } else {
            filterChain.doFilter(request, response);
        }
    }

    private void sendErrorResponse(HttpServletResponse response, String message) throws IOException {
        log.error(message);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.getWriter().write("{\"error\": \""+message+"\"}");
    }

}