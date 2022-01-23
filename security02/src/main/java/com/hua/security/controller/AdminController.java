package com.hua.security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequestMapping("/admin")
public class AdminController {   // 只能拥有 ROLE_ADMIN 权限的用户访问

    @GetMapping("/hello")
    @ResponseBody
    public String hello() {
        return "hello，admin！！！";
    }
}
