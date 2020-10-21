package com.qmy.springsecurity.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * @author qumy
 * @since 2020/10/21 18:54
 */
@Configuration // 标识为配置类
@EnableWebSecurity
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     * 身份认证管理器
     * <ul>
     *  <li>认证信息提供方式（用户名、密码、当前用户的资源权限）</li>
     * <li>可采用内存存储方式，也可能采用数据库方式等</li>
     * <ul>
     *
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        super.configure(auth);
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
     * <ul>
     *  <li>拦截的哪一些资源</li>
     *  <li>资源所对应的角色权限</li>
     *  <li>定义认证方式： httpBasic 、 httpForm</li>
     *  <li>定制登录页面、登录请求地址、错误处理方式</li>
     *  <li>自定义 spring security 过滤器等</li>
     * <ul>
     *
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        super.configure(http);
    }
}
