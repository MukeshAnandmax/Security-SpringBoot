package com.practice.springsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class Config extends WebSecurityConfigurerAdapter {

    private  static final String AUTH1="auth1";
    private  static final String AUTH2="auth2";

    //Authentication purpose
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
       auth.inMemoryAuthentication().withUser("mukesh").password("mukesh123").authorities(AUTH1)
               .and().withUser("sharika").password("sharika123").authorities(AUTH1,AUTH2);
    }


    //Authorization purpose
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.httpBasic().and()
                .authorizeRequests().antMatchers("/auth1/**").hasAuthority(AUTH1)
                .antMatchers("/auth2").hasAuthority(AUTH2)
                .antMatchers("/**").permitAll().and().formLogin();
    }

    @Bean
    public PasswordEncoder getPasswordEncoder(){

        return NoOpPasswordEncoder.getInstance();
    }

}
