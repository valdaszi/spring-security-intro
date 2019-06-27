package lt.bta.java2.sprngsec;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import java.util.Arrays;
import java.util.List;

@SpringBootApplication
public class SprngSecApplication {

    public static void main(String[] args) {
        SpringApplication.run(SprngSecApplication.class, args);
    }

}

@Controller
class Ctrl {

    @RolesAllowed("USER")
    @GetMapping("/user")
    public String user() {
        return "user";
    }

    @RolesAllowed("ADMIN")
    @GetMapping("/admin")
    public String admin() {
        return "admin";
    }

    @PermitAll
    @GetMapping("/any")
    public String any() {
        return "any";
    }
}

@Configuration
class MVCConfig implements WebMvcConfigurer {

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/error").setViewName("error");
    }
}

// Enablina security anotacijas kaip kad @RolesAllowed, @PermitAll, @DenyAll ...
@EnableGlobalMethodSecurity(jsr250Enabled = true)
@Configuration
class SecurityConfig extends WebSecurityConfigurerAdapter {


    @Bean
    @Override
    protected UserDetailsService userDetailsService() {
        List<UserDetails> users = Arrays.asList(
                User.withDefaultPasswordEncoder().username("user").password("user").roles("USER").build(),
                User.withDefaultPasswordEncoder().username("admin").password("admin").roles("USER", "ADMIN").build()
        );
        return new InMemoryUserDetailsManager(users);
    }


//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
//        auth
//                .inMemoryAuthentication()
//                .withUser("user").password(encoder.encode("user")).roles("USER")
//                .and()
//                .withUser("admin").password(encoder.encode("admin")).roles("USER", "ADMIN");
//    }


//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http
//                .authorizeRequests()
//                .antMatchers("/").permitAll()
//                .antMatchers("/user").hasRole("USER")
//                .antMatchers("/admin").hasRole("ADMIN")
//                .antMatchers("/any").authenticated()
//                .anyRequest().authenticated()
//
//                .and()
//                .formLogin()
//
//                .and()
//                .logout()
//                .logoutSuccessUrl("/")  // nurodytas URL į kurį nueis po sėkmingo logout'o - pagal nutylėjimą atidaromas login langas
//        ;
//    }


    // Jei naudojame anotacijas, tai HttpSecurity reikia konfiguruoti minimaliai
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().permitAll()

                .and()
                .formLogin()

                .and()
                .logout()
                .logoutSuccessUrl("/")  // nurodytas URL į kurį nueis po sėkmingo logout'o - pagal nutylėjimą atidaromas login langas
        ;
    }
}

