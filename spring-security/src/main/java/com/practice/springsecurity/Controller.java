package com.practice.springsecurity;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Controller {

    @GetMapping("/test")
    public  String test(){
        return "<h1>Spring security testing,Anybody can access.........</h1>";
    }

    @GetMapping("/auth1")
    public  String test1(){
        return "<h1>Hello!! from auth1.........</h1>";
    }
    @GetMapping("/auth2")
    public  String test2(){
        return "<h1>Hello!! from auth2.........</h1>";
    }

}
