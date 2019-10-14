package com.demozi.res.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Created by jianwu6 on 2019/10/14 16:24
 */
@RestController
public class ResController {

    @GetMapping("/api/res")
    @PreAuthorize("#oauth2.clientHasRole('ROLE_CLIENT')")
    public String getRes() {

        return "get resource xxx";
    }

    @GetMapping("/hello")
    public String getUnprotectedRes() {

        return "hello";
    }
}
