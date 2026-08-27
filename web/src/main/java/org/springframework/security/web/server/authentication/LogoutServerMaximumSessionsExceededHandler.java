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

import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.security.core.session.ReactiveSessionInformation;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.util.Assert;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * A {@link ServerMaximumSessionsExceededHandler} that performs logout for the least
 * recently used sessions by making a request to a trusted application logout endpoint.
 *
 * <p>
 * This handler sends the cookies captured when the session was registered to the
 * configured logout URI. The logout URI must therefore identify a trusted endpoint.
 *
 * @author Goutam Adwant
 * @since 7.2
 */
public final class LogoutServerMaximumSessionsExceededHandler implements ServerMaximumSessionsExceededHandler {

	private final Log logger = LogFactory.getLog(getClass());

	private final URI logoutUri;

	private WebClient webClient = WebClient.create();

	private String sessionCookieName = "SESSION";

	private Duration timeout = Duration.ofSeconds(5);

	/**
	 * Creates an instance that sends logout requests to the provided trusted URI.
	 * @param logoutUri an absolute HTTP or HTTPS logout URI
	 */
	public LogoutServerMaximumSessionsExceededHandler(String logoutUri) {
		Assert.hasText(logoutUri, "logoutUri cannot be empty");
		URI uri = URI.create(logoutUri);
		Assert.isTrue(
				uri.isAbsolute() && uri.getHost() != null
						&& ("http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme())),
				"logoutUri must be an absolute HTTP or HTTPS URI");
		this.logoutUri = uri;
	}

	@Override
	public Mono<Void> handle(MaximumSessionsContext context) {
		List<ReactiveSessionInformation> sessions = new ArrayList<>(context.getSessions());
		sessions.removeIf((session) -> session.getSessionId().equals(context.getCurrentSession().getId()));
		sessions.sort(Comparator.comparing(ReactiveSessionInformation::getLastAccessTime));
		int maximumSessionsExceededBy = sessions.size() - context.getMaximumSessionsAllowed() + 1;
		List<ReactiveSessionInformation> leastRecentlyUsedSessionsToLogout = sessions.subList(0,
				maximumSessionsExceededBy);
		return Flux.fromIterable(leastRecentlyUsedSessionsToLogout)
			.concatMap(this::logout)
			.then()
			.onErrorResume((ex) -> handleFailure(context, ex));
	}

	private Mono<Void> logout(ReactiveSessionInformation session) {
		return this.webClient.post()
			.uri(this.logoutUri)
			.headers((headers) -> headers.setAll(session.getAuthorities()))
			.cookies((cookies) -> {
				session.getCookies().forEach(cookies::set);
				cookies.set(this.sessionCookieName, session.getSessionId());
			})
			.retrieve()
			.toBodilessEntity()
			.timeout(this.timeout)
			.then();
	}

	private Mono<Void> handleFailure(MaximumSessionsContext context, Throwable ex) {
		this.logger.debug("Failed to log out an excess session", ex);
		return context.getCurrentSession()
			.invalidate()
			.then(Mono.defer(() -> Mono.error(new SessionAuthenticationException("Maximum sessions exceeded"))));
	}

	/**
	 * Sets the name of the cookie that contains the session identifier. The default is
	 * {@code SESSION}.
	 * @param sessionCookieName the session cookie name
	 */
	public void setSessionCookieName(String sessionCookieName) {
		Assert.hasText(sessionCookieName, "sessionCookieName cannot be empty");
		this.sessionCookieName = sessionCookieName;
	}

	/**
	 * Sets the maximum amount of time to wait for each logout request. The default is
	 * five seconds.
	 * @param timeout the request timeout
	 */
	public void setTimeout(Duration timeout) {
		Assert.notNull(timeout, "timeout cannot be null");
		Assert.isTrue(!timeout.isNegative() && !timeout.isZero(), "timeout must be positive");
		this.timeout = timeout;
	}

	/**
	 * Sets the {@link WebClient} to use for logout requests.
	 * @param webClient the web client to use
	 */
	public void setWebClient(WebClient webClient) {
		Assert.notNull(webClient, "webClient cannot be null");
		this.webClient = webClient;
	}

}
