package jdojo;

import javax.servlet.*;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 * Created by IntelliJ IDEA.
 * User: Camilla
 * Date: 2011-11-17
 * Time: 18:18
 * To change this template use File | Settings | File Templates.
 */
public class SSOAuthenticator implements javax.servlet.Filter {

    public static final String SSO_TOKEN_KEY = "ssoToken";
    private SingleSignOnRegistry ssoRegistry;

    public void init(FilterConfig filterConfig) throws ServletException {

    }

    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        Cookie[] cookies = ((HttpServletRequest) servletRequest).getCookies();
        HttpSession session = ((HttpServletRequest) servletRequest).getSession();

        if (requestContainsValidCookie(cookies) || requestContainsValidSessionToken(session)) {
            filterChain.doFilter(servletRequest, servletResponse);
        } else {
            ((HttpServletResponse)servletResponse).setStatus(401);
        }
    }

    private boolean requestContainsValidSessionToken(HttpSession session) {
        if (session == null || session.getAttribute(SSO_TOKEN_KEY) == null) {
            return false;
        }
        return ssoRegistry.tokenIsValid(session.getAttribute(SSO_TOKEN_KEY).toString());
    }

    private boolean requestContainsValidCookie(Cookie[] cookies) {
        if (cookies == null || cookies.length == 0) {
            return false;
        }
        for(Cookie cookie : cookies){
            if(cookie.getName() == "token"){
                if(ssoRegistry.tokenIsValid(cookie.getValue())){
                    return true;
                }
            }
        }
        return false;
    }

    public void destroy() {
    }

    public void setSingleSignOnRegistry(SingleSignOnRegistry ssoRegistry) {
       this.ssoRegistry = ssoRegistry;
    }
}
