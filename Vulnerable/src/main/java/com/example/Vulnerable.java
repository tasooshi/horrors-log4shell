package com.example;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.springframework.boot.SpringApplication;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;


@SpringBootApplication
@RestController
public class Vulnerable {

    static final Logger logger = LogManager.getLogger(Vulnerable.class);

    @GetMapping("/")
    String home() {
        return "<html><head><title>Vulnerable Application</title></head><body><h1>Welcome!</h1><hr>Here's the <a href=\"/endpoint\">endpoint</a></body></html>";
    }

    @RequestMapping("/endpoint")
    String endpoint(
            @RequestHeader(name="User-Agent") String userAgent,
            @RequestParam(value="somefield", defaultValue="default") String somefield,
            @RequestParam(value="secondfield", defaultValue="default") String secondfield) {
        logger.info("User-Agent:" + userAgent);
        logger.info("somefield:" + somefield);
        logger.info("secondfield:" + secondfield);
        return "<html><head><title>Vulnerable Application</title></head><body><form method=\"POST\"><input name=\"somefield\" type=\"text\"><input name=\"secondfield\" type=\"text\"><button type=\"submit\">Submit</button></form></body></html>";
    }

    public static void main(String[] args) {
        SpringApplication.run(Vulnerable.class, args);
    }

}
