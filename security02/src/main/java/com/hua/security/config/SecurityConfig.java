package com.hua.security.config;

import com.hua.security.service.impl.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    /**
     * 定制用户认证管理器来实现用户认证
     *  1. 提供用户认证所需信息（用户名、密码、当前用户的资源权）
     *  2. 可采用内存存储方式，也可能采用数据库方式
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 不再使用内存方式存储用户认证信息，而是动态从数据库中获取
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }

    /**
     * 定制基于 HTTP 请求的用户访问控制
     *  1. 配置拦截的哪一些资源
     *  2. 配置资源所对应的角色权限
     *  3. 定义认证方式：HttpBasic、HttpForm
     *  4. 定制登录页面、登录请求地址、错误处理方式
     *  5. 自定义 Spring Security 过滤器等
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin()
                // 设置登录页面的访问路径，默认为 /login，GET 请求；该路径不设限访问
                .loginPage("/login/page")
                // 设置登录表单提交路径，默认为 loginPage() 设置的路径，POST 请求
                .loginProcessingUrl("/login/form")
                // 设置登录表单中的用户名参数，默认为 username
                .usernameParameter("name")
                // 设置登录表单中的密码参数，默认为 password
                .passwordParameter("pwd")
                // 认证成功处理，如果存在原始访问路径，则重定向到该路径；如果没有，则重定向 /index
                .defaultSuccessUrl("/index")
                // 认证失败处理，重定向到指定地址，默认为 loginPage() + ?error；该路径不设限访问
                .failureUrl("/login/page?error");

        // 开启基于 HTTP 请求访问控制
        http.authorizeRequests()
                // 以下访问不需要任何权限，任何人都可以访问
                .antMatchers("/login/page").permitAll()
                // 以下访问需要 ROLE_ADMIN 权限
                .antMatchers("/admin/**").hasRole("ADMIN")
                // 以下访问需要 ROLE_USER 权限
                .antMatchers("/user/**").hasAuthority("ROLE_USER")
                // 其它任何请求访问都需要先通过认证
                .anyRequest().authenticated();

        // 关闭 csrf 防护
        http.csrf().disable();
    }

    /**
     * 定制一些全局性的安全配置，例如：不拦截静态资源的访问
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
        // 静态资源的访问不需要拦截，直接放行
        web.ignoring().antMatchers("/**/*.css", "/**/*.js", "/**/*.png", "/**/*.jpg", "/**/*.jpeg");
    }

    /**
     * 配置加密算法
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        // 使用 BCryptPasswordEncoder 密码编码器，该编码器会将随机产生的 salt 混入最终生成的密文中
        return new BCryptPasswordEncoder();
    }

}
