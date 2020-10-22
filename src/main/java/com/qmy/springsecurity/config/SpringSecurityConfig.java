package com.qmy.springsecurity.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * @author qumy
 * @since 2020/10/21 18:54
 */
@Slf4j
@Configuration // 标识为配置类
@EnableWebSecurity
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * 身份认证管理器
     * <ol>
     *  <li>认证信息提供方式（用户名、密码、当前用户的资源权限）</li>
     * <li>可采用内存存储方式，也可能采用数据库方式等</li>
     * <ol>
     *
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        super.configure(auth);
        // 数据库存储的密码必须是加密后的，不然会报错：There is no PasswordEncoder mapped for the id "null"
        String password = passwordEncoder.encode("1234");
        log.info("加密之后存储的密码：" + password);
        // 设置用户名和角色
        auth.inMemoryAuthentication().withUser("admin")
                .password(password).authorities("ADMIN");
    }

    @Override
    public void init(WebSecurity web) throws Exception {
        super.init(web);
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        super.configure(web);
    }

    /**
     * 资源权限配置（过滤器链）
     * <ol>
     *  <li>拦截的哪一些资源</li>
     *  <li>资源所对应的角色权限</li>
     *  <li>定义认证方式： httpBasic 、 httpForm</li>
     *  <li>定制登录页面、登录请求地址、错误处理方式</li>
     *  <li>自定义 spring security 过滤器等</li>
     * <ol>
     *
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        super.configure(http);
        // 采用 httpBasic认证方式
        http.httpBasic()
                // 表单登录方式
                .and()
                // 认证请求
                .authorizeRequests()
                .anyRequest()
                //所有访问该应用的http请求都要通过身份认证才可以访问
                .authenticated()
        ; // 注意不要少了分号
    }

}
