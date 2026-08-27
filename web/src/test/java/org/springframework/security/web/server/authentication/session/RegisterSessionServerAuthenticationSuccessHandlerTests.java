/*
 * Copyright 2004-present the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web.server.authentication.session;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;

import org.springframework.http.HttpCookie;
import org.springframework.http.ResponseCookie;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.mock.web.server.MockWebSession;
import org.springframework.security.authentication.TestAuthentication;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.ReactiveSessionInformation;
import org.springframework.security.core.session.ReactiveSessionRegistry;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.RegisterSessionServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.csrf.DefaultCsrfToken;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.server.WebSession;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.entry;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class RegisterSessionServerAuthenticationSuccessHandlerTests {

	RegisterSessionServerAuthenticationSuccessHandler strategy;

	@Mock
	ReactiveSessionRegistry sessionRegistry;

	@Mock
	WebFilterChain filterChain;

	WebSession session = new MockWebSession();

	ServerWebExchange serverWebExchange = MockServerWebExchange.builder(MockServerHttpRequest.get(""))
		.session(this.session)
		.build();

	@BeforeEach
	void setup() {
		this.strategy = new RegisterSessionServerAuthenticationSuccessHandler(this.sessionRegistry);
	}

	@Test
	void constructorWhenSessionRegistryNullThenException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new RegisterSessionServerAuthenticationSuccessHandler(null))
			.withMessage("sessionRegistry cannot be null");
	}

	@Test
	void onAuthenticationWhenSessionExistsThenSaveSessionInformation() {
		given(this.sessionRegistry.saveSessionInformation(any())).willReturn(Mono.empty());
		WebFilterExchange webFilterExchange = new WebFilterExchange(this.serverWebExchange, this.filterChain);
		Authentication authentication = TestAuthentication.authenticatedUser();
		this.strategy.onAuthenticationSuccess(webFilterExchange, authentication).block();
		ArgumentCaptor<ReactiveSessionInformation> captor = ArgumentCaptor.forClass(ReactiveSessionInformation.class);
		verify(this.sessionRegistry).saveSessionInformation(captor.capture());
		assertThat(captor.getValue().getSessionId()).isEqualTo(this.session.getId());
		assertThat(captor.getValue().getLastAccessTime()).isEqualTo(this.session.getLastAccessTime());
		assertThat(captor.getValue().getPrincipal()).isEqualTo(authentication.getPrincipal());
		assertThat(captor.getValue().getAuthorities()).isEmpty();
		assertThat(captor.getValue().getCookies()).isEmpty();
	}

	@Test
	void onAuthenticationWhenCredentialCaptureNotConfiguredThenDoesNotCaptureCredentials() {
		given(this.sessionRegistry.saveSessionInformation(any())).willReturn(Mono.empty());
		this.serverWebExchange.getAttributes()
			.put(CsrfToken.class.getName(), Mono.error(new AssertionError("CSRF token should not be subscribed")));
		WebFilterExchange webFilterExchange = new WebFilterExchange(this.serverWebExchange, this.filterChain);

		this.strategy.onAuthenticationSuccess(webFilterExchange, TestAuthentication.authenticatedUser()).block();

		ArgumentCaptor<ReactiveSessionInformation> captor = ArgumentCaptor.forClass(ReactiveSessionInformation.class);
		verify(this.sessionRegistry).saveSessionInformation(captor.capture());
		assertThat(captor.getValue().getAuthorities()).isEmpty();
		assertThat(captor.getValue().getCookies()).isEmpty();
	}

	@Test
	void onAuthenticationWhenCsrfTokenExistsThenSavesCsrfTokenAuthority() {
		this.strategy = new RegisterSessionServerAuthenticationSuccessHandler(this.sessionRegistry,
				List.of("XSRF-TOKEN"));
		given(this.sessionRegistry.saveSessionInformation(any())).willReturn(Mono.empty());
		CsrfToken csrfToken = new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "token");
		ServerWebExchange serverWebExchange = MockServerWebExchange
			.builder(MockServerHttpRequest.get("")
				.cookie(new HttpCookie("XSRF-TOKEN", "cookie-token"), new HttpCookie("OTHER", "other-cookie")))
			.session(this.session)
			.build();
		serverWebExchange.getAttributes().put(CsrfToken.class.getName(), Mono.just(csrfToken));
		WebFilterExchange webFilterExchange = new WebFilterExchange(serverWebExchange, this.filterChain);

		this.strategy.onAuthenticationSuccess(webFilterExchange, TestAuthentication.authenticatedUser()).block();

		ArgumentCaptor<ReactiveSessionInformation> captor = ArgumentCaptor.forClass(ReactiveSessionInformation.class);
		verify(this.sessionRegistry).saveSessionInformation(captor.capture());
		assertThat(captor.getValue().getAuthorities()).containsOnly(entry("X-CSRF-TOKEN", "token"));
		assertThat(captor.getValue().getCookies()).containsOnly(entry("XSRF-TOKEN", "cookie-token"));
	}

	@Test
	void onAuthenticationWhenCsrfCookieGeneratedThenSavesResponseCookie() {
		this.strategy = new RegisterSessionServerAuthenticationSuccessHandler(this.sessionRegistry,
				List.of("XSRF-TOKEN"));
		given(this.sessionRegistry.saveSessionInformation(any())).willReturn(Mono.empty());
		CsrfToken csrfToken = new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "token");
		ServerWebExchange serverWebExchange = MockServerWebExchange.builder(MockServerHttpRequest.get(""))
			.session(this.session)
			.build();
		Mono<CsrfToken> deferredCsrfToken = Mono.fromSupplier(() -> {
			serverWebExchange.getResponse().addCookie(ResponseCookie.from("XSRF-TOKEN", "generated-cookie").build());
			return csrfToken;
		});
		serverWebExchange.getAttributes().put(CsrfToken.class.getName(), deferredCsrfToken);
		WebFilterExchange webFilterExchange = new WebFilterExchange(serverWebExchange, this.filterChain);

		this.strategy.onAuthenticationSuccess(webFilterExchange, TestAuthentication.authenticatedUser()).block();

		ArgumentCaptor<ReactiveSessionInformation> captor = ArgumentCaptor.forClass(ReactiveSessionInformation.class);
		verify(this.sessionRegistry).saveSessionInformation(captor.capture());
		assertThat(captor.getValue().getAuthorities()).containsOnly(entry("X-CSRF-TOKEN", "token"));
		assertThat(captor.getValue().getCookies()).containsOnly(entry("XSRF-TOKEN", "generated-cookie"));
	}

	@Test
	void onAuthenticationWhenCookieNamesConfiguredThenCapturesOnlyConfiguredCookies() {
		this.strategy = new RegisterSessionServerAuthenticationSuccessHandler(this.sessionRegistry,
				List.of("LOGOUT_STATE"));
		given(this.sessionRegistry.saveSessionInformation(any())).willReturn(Mono.empty());
		ServerWebExchange serverWebExchange = MockServerWebExchange
			.builder(MockServerHttpRequest.get("")
				.cookie(new HttpCookie("LOGOUT_STATE", "logout-cookie"), new HttpCookie("XSRF-TOKEN", "csrf-cookie")))
			.session(this.session)
			.build();
		WebFilterExchange webFilterExchange = new WebFilterExchange(serverWebExchange, this.filterChain);

		this.strategy.onAuthenticationSuccess(webFilterExchange, TestAuthentication.authenticatedUser()).block();

		ArgumentCaptor<ReactiveSessionInformation> captor = ArgumentCaptor.forClass(ReactiveSessionInformation.class);
		verify(this.sessionRegistry).saveSessionInformation(captor.capture());
		assertThat(captor.getValue().getCookies()).containsOnly(entry("LOGOUT_STATE", "logout-cookie"));
	}

	@Test
	void constructorWhenCookieNamesContainsEmptyValueThenException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new RegisterSessionServerAuthenticationSuccessHandler(this.sessionRegistry, List.of("")))
			.withMessage("cookieNames cannot contain empty values");
	}

}
