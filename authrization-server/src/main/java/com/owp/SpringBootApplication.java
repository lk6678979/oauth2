package com.owp;

import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.web.bind.annotation.RestController;

/**
 * Created by hxy on 2018/6/20
 * E-mail:hxyHelloWorld@163.com
 * github:https://github.com/haoxiaoyong1014
 */
@RestController
@org.springframework.boot.autoconfigure.SpringBootApplication
@Slf4j
public class SpringBootApplication {

    protected final Logger log = LoggerFactory.getLogger(this.getClass());

    public static void main(String[] args) {
        SpringApplication.run(SpringBootApplication.class, args);
    }

//    @GetMapping("/userJwt")
//    public Object getCurrentUserJwt(Authentication authentication, HttpServletRequest request) throws UnsupportedEncodingException {
//        log.info("【SecurityOauth2Application】 getCurrentUserJwt authentication={}", JsonUtil.toJson(authentication));
//
//        String header = request.getHeader("Authorization");
//        String token = StringUtils.substringAfter(header, "bearer ");
//
//        Claims claims = Jwts.parser().setSigningKey(oAuth2Properties.getJwtSigningKey().getBytes("UTF-8")).parseClaimsJws(token).getBody();
//        String blog = (String) claims.get("blog");
//        log.info("【SecurityOauth2Application】 getCurrentUser1 blog={}", blog);
//
//        return authentication;
//    }
//
//    @GetMapping("/userRedis")
//    @PreAuthorize("hasAnyAuthority('select')")
//    public Object getCurrentUserRedis(Authentication authentication) {
//        log.info("【SecurityOauth2Application】 getCurrentUserRedis authentication={}", JsonUtil.toJson(authentication));
//        return authentication;
//    }

}
