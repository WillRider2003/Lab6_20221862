package com.example.lab_gticss.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration
public class WebSecurityConfig<HttpSecurity> {

    final DataSource dataSource;

    public WebSecurityConfig(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsManager users(DataSource dataSource){
        JdbcUserDetailsManager users = new JdbcUserDetailsManager(dataSource);
        String sql1 = "SELECT email, pwd, activo FROM users WHERE email = ?";
        String sql2 = "SELECT u.email, r.nombre FROM users u "
                + "INNER JOIN rol r ON (u.idrol = r.idrol) "
                + "WHERE u.email = ? and u.activo = 1";

        users.setUsersByUsernameQuery(sql1);
        users.setAuthoritiesByUsernameQuery(sql2);
        return users;
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.formLogin()
                .loginPage("/loginForm")
                .loginProcessingUrl("/processLogin");

        http.authorizeHttpRequests()
                .requestMatchers("/user","/user/**").hasAnyAuthority("admin","user")
                .requestMatchers("/admin","/admin/**").hasAuthority("admin")
                .anyRequest().permitAll();

        return http.build();

    }

}
