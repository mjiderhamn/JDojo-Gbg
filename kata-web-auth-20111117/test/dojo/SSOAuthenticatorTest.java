package dojo;

import jdojo.SSOAuthenticator;
import jdojo.SingleSignOnRegistry;
import org.junit.Before;
import org.junit.Test;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import java.io.IOException;

import static org.mockito.Mockito.*;

/**
 * Created by IntelliJ IDEA.
 * User: Camilla
 * Date: 2011-11-17
 */
public class SSOAuthenticatorTest {

    public static final String VALID_SSO_TOKEN = "validSSOToken";
    SSOAuthenticator ssoAuthenticator = new SSOAuthenticator();

    HttpServletRequest request = mock(HttpServletRequest.class);
    HttpServletResponse response = mock(HttpServletResponse.class);
    FilterChain filterChain = mock(FilterChain.class);
    private SingleSignOnRegistry ssoRegistry = mock(SingleSignOnRegistry.class);

    @Before
    public void setup() {
        ssoAuthenticator.setSingleSignOnRegistry(ssoRegistry);
    }

    @Test
    public void notLoggedInMeansError() throws Exception {
        ssoAuthenticator.doFilter(request, response, filterChain);

        verify(response).setStatus(401);
        verifyZeroInteractions(filterChain); // No forward
    }

    @Test
    public void cookieWithInvalidToken() throws Exception {
        when(request.getCookies()).thenReturn(new Cookie[]{new Cookie("token", "123")});

        ssoAuthenticator.doFilter(request, response, filterChain);

        verify(response).setStatus(401);
        verifyZeroInteractions(filterChain); // No forward
    }

    @Test
    public void aRequestWithCookieWithValidTokenIsPassedOnDownTheFilterChain() throws Exception {
        // given
        when(request.getCookies()).thenReturn(new Cookie[]{new Cookie("token", "X")});
        when(ssoRegistry.tokenIsValid("X")).thenReturn(true);

        ssoAuthenticator.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verifyZeroInteractions(response);
    }

    @Test
    public void aRequestWithTwoCookieWithTheSecondContainingValidTokenIsPassedOnDownTheFilterChain() throws Exception {
        // given
        when(request.getCookies()).thenReturn(new Cookie[]{new Cookie("no", "wrong"), new Cookie("token", "right")});
        when(ssoRegistry.tokenIsValid("right")).thenReturn(true);

        ssoAuthenticator.doFilter(request, response, filterChain);

        verify(ssoRegistry).tokenIsValid("right");
        verify(filterChain).doFilter(request, response);
        verifyZeroInteractions(response);
    }

    @Test
    public void atwoCookiesContainCorrectValueButSecondHasTheExpectedSSOTokenName() throws Exception {
        // given
        when(request.getCookies()).thenReturn(new Cookie[]{new Cookie("no", "wrong"), new Cookie("token", "right")});
        when(ssoRegistry.tokenIsValid("right")).thenReturn(true);

        ssoAuthenticator.doFilter(request, response, filterChain);

        verify(ssoRegistry, times(1)).tokenIsValid("right");
        verifyNoMoreInteractions(ssoRegistry);
        verify(filterChain).doFilter(request, response);
        verifyZeroInteractions(response);
    }

    @Test
    public void atwoCookiesContainCorrectValueButBothHasTheExpectedSSOTokenName() throws Exception {
        // given
        when(request.getCookies()).thenReturn(new Cookie[]{new Cookie("token", "wrong"), new Cookie("token", "right")});
        when(ssoRegistry.tokenIsValid("right")).thenReturn(true);

        ssoAuthenticator.doFilter(request, response, filterChain);

        verify(ssoRegistry).tokenIsValid("right");
        verify(ssoRegistry).tokenIsValid("wrong");

        verify(filterChain).doFilter(request, response);
        verifyZeroInteractions(response);
    }

    @Test
    public void validSessionToken() throws IOException, ServletException {
        HttpSession session = mock(HttpSession.class);
        when(session.getAttribute("ssoToken")).thenReturn(VALID_SSO_TOKEN);
        when(ssoRegistry.tokenIsValid(VALID_SSO_TOKEN)).thenReturn(true);
        when(request.getSession()).thenReturn(session);

        ssoAuthenticator.doFilter(request, response, filterChain);

        verify(ssoRegistry).tokenIsValid(VALID_SSO_TOKEN);
        verify(filterChain).doFilter(request, response);
        verifyZeroInteractions(response);
    }
}
