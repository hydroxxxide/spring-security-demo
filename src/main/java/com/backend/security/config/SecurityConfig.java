package com.backend.security.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Slf4j
@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final CorsFilter corsFilter;
    private final JwtAuthFilter jwtAuthFilter;
    private static final String[] WHITE_LIST_URL_DEV = {
            "/identity/",
            "/v1/api/common/",
            "/login/",

            "/actuator/",

            "/v3/api-docs",
            "/v3/api-docs/",

            "/swagger-resources",
            "/swagger-resources/",
            "/swagger-ui.html",
            "/swagger-ui/",

            "/configuration/ui",
            "/configuration/security",

            "/webjars/"
    };



    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {

        log.info(" ----  Info:" + httpSecurity);
        httpSecurity
                .addFilterBefore(corsFilter, ChannelProcessingFilter.class)
                .cors(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(WHITE_LIST_URL_DEV).permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .requestMatchers("/user").hasRole("USER")
                        .anyRequest().permitAll()
                )
//                .exceptionHandling(exh -> exh.authenticationEntryPoint(new AuthEntryPoint()))

                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);


        return httpSecurity.build();
    }

}