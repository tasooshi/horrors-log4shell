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
        return "<html><head><title>Vulnerable Application</title></head><body>Welcome!</body></html>";
    }

    @RequestMapping("/endpoint")
    String endpoint(@RequestHeader(name="User-Agent") String userAgent, @RequestParam(value="somefield", defaultValue="default") String somefield) {
        System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase", String.valueOf(true));
        logger.info("User-Agent:" + userAgent.substring(1));
	    logger.info("User-Agent:" + userAgent);
        logger.info("somefield:" + somefield);
        return "<html><head><title>Vulnerable Application</title></head><body><form><input name=\"somefield\" type=\"text\"><button type=\"submit\">Submit</button></form></body></html>";
    }

    public static void main(String[] args) {
        SpringApplication.run(Vulnerable.class, args);
    }

}