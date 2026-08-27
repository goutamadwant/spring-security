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

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import reactor.core.publisher.Mono;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.ReactiveSessionInformation;
import org.springframework.security.core.session.ReactiveSessionRegistry;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.util.Assert;

/**
 * An implementation of {@link ServerAuthenticationSuccessHandler} that will register a
 * {@link ReactiveSessionInformation} with the provided {@link ReactiveSessionRegistry}.
 *
 * @author Marcus da Coregio
 * @since 6.3
 */
public final class RegisterSessionServerAuthenticationSuccessHandler implements ServerAuthenticationSuccessHandler {

	private final ReactiveSessionRegistry sessionRegistry;

	private final boolean captureCredentials;

	private final Set<String> cookieNames;

	public RegisterSessionServerAuthenticationSuccessHandler(ReactiveSessionRegistry sessionRegistry) {
		this(sessionRegistry, Set.of(), false);
	}

	/**
	 * Creates an instance that captures CSRF authorization material and the named cookies
	 * when registering a session.
	 * @param sessionRegistry the session registry
	 * @param cookieNames the cookie names to capture
	 * @since 7.2
	 */
	public RegisterSessionServerAuthenticationSuccessHandler(ReactiveSessionRegistry sessionRegistry,
			Collection<String> cookieNames) {
		this(sessionRegistry, cookieNames, true);
	}

	private RegisterSessionServerAuthenticationSuccessHandler(ReactiveSessionRegistry sessionRegistry,
			Collection<String> cookieNames, boolean captureCredentials) {
		Assert.notNull(sessionRegistry, "sessionRegistry cannot be null");
		Assert.notNull(cookieNames, "cookieNames cannot be null");
		for (String cookieName : cookieNames) {
			Assert.hasText(cookieName, "cookieNames cannot contain empty values");
		}
		this.sessionRegistry = sessionRegistry;
		this.captureCredentials = captureCredentials;
		this.cookieNames = new LinkedHashSet<>(cookieNames);
	}

	@Override
	public Mono<Void> onAuthenticationSuccess(WebFilterExchange exchange, Authentication authentication) {
		Mono<CsrfToken> csrfToken = (this.captureCredentials)
				? exchange.getExchange().getAttribute(CsrfToken.class.getName()) : null;
		return exchange.getExchange().getSession().flatMap((session) -> {
			Mono<Map<String, String>> authorities = (csrfToken != null)
					? csrfToken.map((token) -> Map.of(token.getHeaderName(), token.getToken())) : Mono.just(Map.of());
			return authorities.defaultIfEmpty(Map.of())
				.map((credentials) -> new ReactiveSessionInformation(
						Objects.requireNonNull(authentication.getPrincipal()), session.getId(),
						session.getLastAccessTime(), credentials, getCookies(exchange)));
		}).flatMap(this.sessionRegistry::saveSessionInformation);
	}

	private Map<String, String> getCookies(WebFilterExchange exchange) {
		Map<String, String> cookies = new LinkedHashMap<>();
		for (String cookieName : this.cookieNames) {
			var requestCookie = exchange.getExchange().getRequest().getCookies().getFirst(cookieName);
			if (requestCookie != null) {
				cookies.put(cookieName, requestCookie.getValue());
			}
			var responseCookie = exchange.getExchange().getResponse().getCookies().getFirst(cookieName);
			if (responseCookie != null) {
				cookies.put(cookieName, responseCookie.getValue());
			}
		}
		return cookies;
	}

}
