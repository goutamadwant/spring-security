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

package org.springframework.security.web.server.authentication;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.server.MockWebSession;
import org.springframework.security.authentication.TestAuthentication;
import org.springframework.security.core.session.ReactiveSessionInformation;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.web.reactive.function.client.WebClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class LogoutServerMaximumSessionsExceededHandlerTests {

	private final MockWebServer server = new MockWebServer();

	private LogoutServerMaximumSessionsExceededHandler handler;

	@BeforeEach
	void setup() throws IOException {
		this.server.start();
		this.handler = new LogoutServerMaximumSessionsExceededHandler(this.server.url("/logout").toString());
	}

	@AfterEach
	void tearDown() throws IOException {
		this.server.shutdown();
	}

	@Test
	void handleWhenMaximumSessionsExceededThenLogsOutLeastRecentlyUsedSession() throws InterruptedException {
		this.server.enqueue(new MockResponse().setResponseCode(302));
		ReactiveSessionInformation newer = session("newer", 2, Map.of(), Map.of());
		ReactiveSessionInformation older = session("older", 1, Map.of("X-CSRF-TOKEN", "csrf-token"),
				Map.of("XSRF-TOKEN", "csrf-cookie"));
		MaximumSessionsContext context = context(List.of(newer, older), 2);

		this.handler.handle(context).block();

		assertThat(this.server.getRequestCount()).isOne();
		var request = this.server.takeRequest();
		assertThat(request.getMethod()).isEqualTo("POST");
		assertThat(request.getPath()).isEqualTo("/logout");
		assertThat(request.getHeader(HttpHeaders.COOKIE)).contains("SESSION=older", "XSRF-TOKEN=csrf-cookie");
		assertThat(request.getHeader("X-CSRF-TOKEN")).isEqualTo("csrf-token");
	}

	@Test
	void handleWhenCurrentSessionIsRegisteredThenDoesNotLogoutCurrentSession() throws InterruptedException {
		this.server.enqueue(new MockResponse().setResponseCode(200));
		MockWebSession currentSession = new MockWebSession();
		ReactiveSessionInformation current = session(currentSession.getId(), 1, Map.of(), Map.of());
		ReactiveSessionInformation other = session("other", 2, Map.of(), Map.of());
		MaximumSessionsContext context = context(List.of(current, other), 1, currentSession);

		this.handler.handle(context).block();

		assertThat(this.server.takeRequest().getHeader(HttpHeaders.COOKIE)).isEqualTo("SESSION=other");
	}

	@Test
	void handleWhenCustomSessionCookieNameThenOverridesCapturedCookie() throws InterruptedException {
		this.server.enqueue(new MockResponse().setResponseCode(200));
		this.handler.setSessionCookieName("CUSTOM_SESSION");
		ReactiveSessionInformation session = session("session-id", 1, Map.of(),
				Map.of("CUSTOM_SESSION", "captured-session", "XSRF-TOKEN", "csrf-cookie"));

		this.handler.handle(context(List.of(session), 1)).block();

		String cookie = this.server.takeRequest().getHeader(HttpHeaders.COOKIE);
		assertThat(cookie).contains("CUSTOM_SESSION=session-id", "XSRF-TOKEN=csrf-cookie")
			.doesNotContain("captured-session");
	}

	@Test
	void handleWhenLogoutFailsThenInvalidatesCurrentSessionAndRejectsAuthentication() {
		this.server.enqueue(new MockResponse().setResponseCode(500));
		MockWebSession currentSession = new MockWebSession();
		currentSession.start();
		MaximumSessionsContext context = context(List.of(session("session-id", 1, Map.of(), Map.of())), 1,
				currentSession);

		assertThatExceptionOfType(SessionAuthenticationException.class)
			.isThrownBy(() -> this.handler.handle(context).block())
			.withMessage("Maximum sessions exceeded");
		assertThat(currentSession.isStarted()).isFalse();
	}

	@Test
	void handleWhenLogoutTimesOutThenInvalidatesCurrentSessionAndRejectsAuthentication() {
		this.handler.setWebClient(WebClient.builder().exchangeFunction((request) -> Mono.never()).build());
		this.handler.setTimeout(Duration.ofMillis(10));
		MockWebSession currentSession = new MockWebSession();
		currentSession.start();
		MaximumSessionsContext context = context(List.of(session("session-id", 1, Map.of(), Map.of())), 1,
				currentSession);

		assertThatExceptionOfType(SessionAuthenticationException.class)
			.isThrownBy(() -> this.handler.handle(context).block())
			.withMessage("Maximum sessions exceeded");
		assertThat(currentSession.isStarted()).isFalse();
	}

	@Test
	void constructorWhenLogoutUriIsRelativeThenThrowsException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new LogoutServerMaximumSessionsExceededHandler("/logout"))
			.withMessage("logoutUri must be an absolute HTTP or HTTPS URI");
	}

	@Test
	void constructorWhenLogoutUriUsesUnsupportedSchemeThenThrowsException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new LogoutServerMaximumSessionsExceededHandler("file:///logout"))
			.withMessage("logoutUri must be an absolute HTTP or HTTPS URI");
	}

	@Test
	void constructorWhenLogoutUriEmptyThenThrowsException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new LogoutServerMaximumSessionsExceededHandler(""))
			.withMessage("logoutUri cannot be empty");
	}

	@Test
	void setSessionCookieNameWhenEmptyThenThrowsException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.handler.setSessionCookieName(""))
			.withMessage("sessionCookieName cannot be empty");
	}

	@Test
	void setTimeoutWhenNotPositiveThenThrowsException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.handler.setTimeout(Duration.ZERO))
			.withMessage("timeout must be positive");
	}

	@Test
	void setWebClientWhenNullThenThrowsException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.handler.setWebClient(null))
			.withMessage("webClient cannot be null");
	}

	private MaximumSessionsContext context(List<ReactiveSessionInformation> sessions, int maximumSessions) {
		return context(sessions, maximumSessions, new MockWebSession());
	}

	private MaximumSessionsContext context(List<ReactiveSessionInformation> sessions, int maximumSessions,
			MockWebSession currentSession) {
		return new MaximumSessionsContext(TestAuthentication.authenticatedUser(), sessions, maximumSessions,
				currentSession);
	}

	private ReactiveSessionInformation session(String sessionId, long lastAccessTime, Map<String, String> authorities,
			Map<String, String> cookies) {
		return new ReactiveSessionInformation("principal", sessionId, Instant.ofEpochMilli(lastAccessTime), authorities,
				cookies);
	}

}
