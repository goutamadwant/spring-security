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

package org.springframework.security.core.session;

import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import reactor.core.publisher.Mono;

import org.springframework.util.Assert;

public class ReactiveSessionInformation implements Serializable {

	@Serial
	private static final long serialVersionUID = 620L;

	private Instant lastAccessTime;

	private final Object principal;

	private final String sessionId;

	private final Map<String, String> authorities;

	private final Map<String, String> cookies;

	private boolean expired = false;

	public ReactiveSessionInformation(Object principal, String sessionId, Instant lastAccessTime) {
		this(principal, sessionId, lastAccessTime, Collections.emptyMap(), Collections.emptyMap());
	}

	/**
	 * Creates a new instance.
	 * @param principal the principal associated with the session
	 * @param sessionId the session identifier
	 * @param lastAccessTime the time the session was last accessed
	 * @param authorities any material that authorizes operating on the session
	 * @since 7.2
	 */
	public ReactiveSessionInformation(Object principal, String sessionId, Instant lastAccessTime,
			Map<String, String> authorities) {
		this(principal, sessionId, lastAccessTime, authorities, Collections.emptyMap());
	}

	/**
	 * Creates a new instance.
	 * @param principal the principal associated with the session
	 * @param sessionId the session identifier
	 * @param lastAccessTime the time the session was last accessed
	 * @param authorities any material that authorizes operating on the session
	 * @param cookies any cookies needed when operating on the session
	 * @since 7.2
	 */
	public ReactiveSessionInformation(Object principal, String sessionId, Instant lastAccessTime,
			Map<String, String> authorities, Map<String, String> cookies) {
		Assert.notNull(principal, "principal cannot be null");
		Assert.hasText(sessionId, "sessionId cannot be null");
		Assert.notNull(lastAccessTime, "lastAccessTime cannot be null");
		Assert.notNull(authorities, "authorities cannot be null");
		Assert.notNull(cookies, "cookies cannot be null");
		this.principal = principal;
		this.sessionId = sessionId;
		this.lastAccessTime = lastAccessTime;
		this.authorities = new LinkedHashMap<>(authorities);
		this.cookies = new LinkedHashMap<>(cookies);
	}

	public ReactiveSessionInformation withSessionId(String sessionId) {
		return new ReactiveSessionInformation(this.principal, sessionId, this.lastAccessTime, getAuthorities(),
				getCookies());
	}

	public Mono<Void> invalidate() {
		return Mono.fromRunnable(() -> this.expired = true);
	}

	public Mono<Void> refreshLastRequest() {
		this.lastAccessTime = Instant.now();
		return Mono.empty();
	}

	public Instant getLastAccessTime() {
		return this.lastAccessTime;
	}

	public Object getPrincipal() {
		return this.principal;
	}

	public String getSessionId() {
		return this.sessionId;
	}

	/**
	 * Returns any material needed to authorize operations on this session.
	 * @return the map of credentials
	 * @since 7.2
	 */
	public Map<String, String> getAuthorities() {
		return (this.authorities != null) ? Collections.unmodifiableMap(this.authorities) : Collections.emptyMap();
	}

	/**
	 * Returns any cookies needed when operating on this session.
	 * @return the map of cookies
	 * @since 7.2
	 */
	public Map<String, String> getCookies() {
		return (this.cookies != null) ? Collections.unmodifiableMap(this.cookies) : Collections.emptyMap();
	}

	public boolean isExpired() {
		return this.expired;
	}

	public void setLastAccessTime(Instant lastAccessTime) {
		this.lastAccessTime = lastAccessTime;
	}

}
