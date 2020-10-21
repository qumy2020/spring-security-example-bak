package com.qmy.springsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * @author qumy
 * @since 2020/10/21 19:09
 */
@Configuration // 标识为配置类
public class PasswordEncoderConfig extends BCryptPasswordEncoder {

    @Bean
    public PasswordEncoder passwordEncoder() {
        // 明文+随机盐值加密存储
//        加密的最终结果分为两部分
//        一、盐值 + MD5(password+盐值), 调用 matches(…) 方法的时候，
//        先从密文中得到盐值，用该盐值加密明文和最终密文作对比。
//        这样可以避免有一个密码被破解, 其他相同的密码的帐户都可以破解。
//        因为通过当前机制相同密码生成的密文都不一样。
//        二、加密过程（注册）：
//        aaa (盐值) + 123(密码明文) > 生成密文 >
//        最终结果 盐值.密文：aaa.asdlkf
//        存入数据库校验过程（登录）： aaa (盐值, 数据库中得到) + 123(用户输入密码)> 生成密文 aaa.asdlkf，与数据库对比一致密码正确。
        return new BCryptPasswordEncoder();
    }
}
