## Spring Cloud Gateway OAuth2 SSO Sample Application

It`s a sample application which how to achieve SSO for your microservices with usage of new [Spring Cloud Gateway](https://spring.io/projects/spring-cloud-gateway) as your API gateway and also with [OAuth2](https://oauth.net/2/) authorization protocol and [JWT](https://jwt.io/) tokens.

##### Sample dependencies

 * Spring Boot 2.1
 * Spring Cloud Gateway 2.1.M1
 * Spring Security 5.1.1
 
 The main idea of this sample is to show how you can achieve functionality described in references below (where Zuul is used as your API Gateway)
 but with usage of new Spring Cloud Gateway provided with Spring Boot 2 and also with [reactive approach](https://projectreactor.io/) (a new feature of [Spring 5](https://spring.io/blog/2016/09/22/new-in-spring-5-functional-web-framework)).
 
 ##### References:
  * [spring OAuth2 SSO tutorial](https://spring.io/blog/2015/02/03/sso-with-oauth2-angular-js-and-spring-security-part-v) 
  * [sso-spring-security-oauth2](https://www.baeldung.com/)
  * [jwt tokens example](https://github.com/monkey-codes/spring-boot-authentication)
  * [microservices-security-with-oauth2](https://piotrminkowski.wordpress.com/2017/02/22/microservices-security-with-oauth2/)     
