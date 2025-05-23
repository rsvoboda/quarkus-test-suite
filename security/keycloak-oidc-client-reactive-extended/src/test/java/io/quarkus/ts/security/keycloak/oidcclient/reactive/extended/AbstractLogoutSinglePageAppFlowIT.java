package io.quarkus.ts.security.keycloak.oidcclient.reactive.extended;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.htmlunit.SilentCssErrorHandler;
import org.htmlunit.WebClient;
import org.htmlunit.WebResponse;
import org.htmlunit.html.HtmlForm;
import org.htmlunit.html.HtmlPage;
import org.htmlunit.util.Cookie;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import io.quarkus.test.bootstrap.KeycloakService;
import io.quarkus.test.bootstrap.LookupService;
import io.quarkus.test.bootstrap.Protocol;
import io.quarkus.test.bootstrap.RestService;
import io.quarkus.test.services.QuarkusApplication;
import io.quarkus.test.utils.TestExecutionProperties;
import io.quarkus.ts.security.keycloak.oidcclient.reactive.extended.tokens.LogoutFlow;

public abstract class AbstractLogoutSinglePageAppFlowIT {

    static final String REALM_DEFAULT = "quarkus";

    @LookupService
    static KeycloakService keycloak;

    @QuarkusApplication(classes = { LogoutFlow.class })
    static RestService app = new RestService()
            .withProperty("keycloak.url", () -> keycloak.getURI(Protocol.HTTP).toString())
            .withProperty("keycloak.origin", () -> {
                if (TestExecutionProperties.isOpenshiftPlatform()) {
                    // in OpenShift we need scheme + host
                    return keycloak.getURI(Protocol.HTTP).getRestAssuredStyleUri();
                } else {
                    // on Bare Metal we need scheme + host + port
                    return "${keycloak.url}";
                }
            })
            .withProperties("logout.properties");

    @Tag("QUARKUS-2491")
    @Test
    public void singlePageAppLogoutFlow() throws IOException {
        try (final WebClient webClient = createWebClient()) {
            String content = makeHttpPostFormLogin(webClient, "/code-flow", "alice", "alice")
                    .getContentAsString();

            assertThat(content, containsString("alice, cache size: 0"));
            assertTrue(isSessionCookiePresent(webClient));

            HtmlPage page = webClient.getPage(app.getURI(Protocol.HTTP).toString() + "/code-flow/logout");
            assertThat(page.getBody().asNormalizedText(), containsString("You are logged out"));
            assertFalse(isSessionCookiePresent(webClient));

            // double-check session is not valid anymore
            boolean isLoginPage = isRedirectedToLoginPage(webClient, "/code-flow/authenticated");
            assertTrue(isLoginPage, "Session is still valid");

            // Clear the post logout cookie
            webClient.getCookieManager().clearCookies();
        }
    }

    private boolean isRedirectedToLoginPage(WebClient webClient, String resourceURL) throws IOException {
        HtmlPage page = webClient.getPage(app.getURI(Protocol.HTTP).toString() + resourceURL);
        return !Objects.isNull(page.getHtmlElementById("kc-form-login"));
    }

    private WebResponse makeHttpPostFormLogin(WebClient webClient, String loginPath, String user, String pwd)
            throws IOException {
        HtmlPage page = webClient.getPage(app.getURI(Protocol.HTTP).toString() + loginPath);
        HtmlForm form = page.getHtmlElementById("kc-form-login");
        form.getInputByName("username").type(user);
        form.getInputByName("password").type(pwd);

        return form.getButtonByName("login").click().getWebResponse();
    }

    private WebClient createWebClient() {
        WebClient webClient = new WebClient();
        webClient.setCssErrorHandler(new SilentCssErrorHandler());
        Logger.getLogger("org.htmlunit.css").setLevel(Level.OFF);
        webClient.getOptions().setRedirectEnabled(true);
        return webClient;
    }

    /**
     * Search for "q_session" cookie.
     * This might be one cookie, or it might be chunked into several ones,
     * which are named "q_session_chunk_1" etc.
     *
     * @return True if cookie is present, chunked or not. False otherwise.
     */
    private boolean isSessionCookiePresent(WebClient webClient) {
        for (Cookie cookie : webClient.getCookieManager().getCookies()) {
            if (cookie.getName().startsWith("q_session")) {
                return true;
            }
        }
        return false;
    }
}
