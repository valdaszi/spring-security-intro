# Spring Security

### Reference Documentation
For further reference, please consider the following sections:

* [Official Gradle documentation](https://docs.gradle.org)

### Guides
The following guides illustrate how to use some features concretely:

* [Building a RESTful Web Service](https://spring.io/guides/gs/rest-service/)
* [Serving Web Content with Spring MVC](https://spring.io/guides/gs/serving-web-content/)
* [Building REST services with Spring](https://spring.io/guides/tutorials/bookmarks/)
* [Securing a Web Application](https://spring.io/guides/gs/securing-web/)
* [Spring Boot and OAuth2](https://spring.io/guides/tutorials/spring-boot-oauth2/)
* [Authenticating a User with LDAP](https://spring.io/guides/gs/authenticating-ldap/)
* [Accessing Data with JPA](https://spring.io/guides/gs/accessing-data-jpa/)
* [Accessing data with MySQL](https://spring.io/guides/gs/accessing-data-mysql/)

### Additional Links
These additional references should also help you:

* [Gradle Build Scans – insights for your project's build](https://scans.gradle.com#gradle)

### Kas gali būti svarbu

- __Kaip nurodyti, koks view'as pririštas prie URL nenaudojant kontrolerio__
    
    Pavyzdžiui nurodome, viewą kuris bus rodomas esant klaidai, t.y. koks view'as pririštas prie URL /error:

    ```
    @Configuration
    class MVCConfig implements WebMvcConfigurer {
        @Override
        public void addViewControllers(ViewControllerRegistry registry) {
            registry.addViewController("/error").setViewName("error");
        }
    }
    ```
- __Jei nėra papildomų nustatymų, tai, pagal nutylėjimą, Spring MVC Security aktyvuojama visiems programos URL__
    
    Sukuriamas vienas vartotojas vardu 'user' su atsitiktiniu slaptažodžiu, kuris būna matyti konsolėje 
    startavus aplikaciją
    
- __Jei norime kažką pakeisti, tai galima padaryti extendinant WebSecurityConfigurerAdapter klasę:__
    ```
    @Configuration
    class SecurityConfig extends WebSecurityConfigurerAdapter {
        ...
    }
    ```
- __Ką daryti jei norime turėti kelis vartotojus su skirtingomis rolėmis?__
    
    Tai galima padaryti keliais būdais:

    - perrašyti configure(AuthenticationManagerBuilder auth) metodą:
        ```
        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
            auth
                .inMemoryAuthentication()
                .withUser("user").password(encoder.encode("user")).roles("USER")
                .and()
                .withUser("admin").password(encoder.encode("admin")).roles("USER", "ADMIN");
        }
        ``` 
        
    - perrašyti metodą userDetailsService() ir sukurti bean'ą: 
        ```
        @Bean
        @Override
        protected UserDetailsService userDetailsService() {
            List<UserDetails> users = Arrays.asList(
                User.withDefaultPasswordEncoder().username("user").password("user").roles("USER").build(),
                User.withDefaultPasswordEncoder().username("admin").password("admin").roles("USER", "ADMIN").build()
            );
            return new InMemoryUserDetailsManager(users);
        }

        ```
- __Ką daryti jei norime nurodyti kokios rolės reikalingos norint prieiti prie vieno ar kito URL?__
    
    Keli sprendimai:
    
    - perrašyti configure(HttpSecurity http) metodą:
        ```
         @Override
         protected void configure(HttpSecurity http) throws Exception {
             http
                .authorizeRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin").hasRole("ADMIN")
                .antMatchers("/any").authenticated()
                .anyRequest().authenticated()
                
                .and()
                .formLogin()
                
                .and()
                .logout()
                .logoutSuccessUrl("/")  // nurodytas URL į kurį nueis po sėkmingo logout'o - pagal nutylėjimą atidaromas login langas
             ;
         }

        ```
        
    - panaudot java standartines anotacijas kaip kad __@PermitAll__, __@RolesAllowed__ ir pan.
        Kad šios anotaciojos pradėtų veikti reikia konfiguracinę klasę anotuoti su __@EnableGlobalMethodSecurity__.
        ```
        @EnableGlobalMethodSecurity(jsr250Enabled = true)
        @Configuration
        class SecurityConfig extends WebSecurityConfigurerAdapter {
            ...
        }

        ```
        
        Taip padarius, jau galime kontrolerius ir/ar jų metodus anotuoti nurodant teises ir roles:
        ```
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
        ```
