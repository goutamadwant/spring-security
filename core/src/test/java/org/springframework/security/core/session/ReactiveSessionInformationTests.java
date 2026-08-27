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

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.entry;

class ReactiveSessionInformationTests {

	@Test
	void constructorWhenAuthoritiesProvidedThenCopiesAuthorities() {
		Map<String, String> authorities = new HashMap<>();
		Map<String, String> cookies = new HashMap<>();
		authorities.put("X-CSRF-TOKEN", "token");
		cookies.put("XSRF-TOKEN", "cookie-token");
		ReactiveSessionInformation information = new ReactiveSessionInformation("principal", "session-id",
				Instant.now(), authorities, cookies);

		authorities.clear();
		cookies.clear();

		assertThat(information.getAuthorities()).containsOnly(entry("X-CSRF-TOKEN", "token"));
		assertThat(information.getCookies()).containsOnly(entry("XSRF-TOKEN", "cookie-token"));
		assertThatExceptionOfType(UnsupportedOperationException.class)
			.isThrownBy(() -> information.getAuthorities().clear());
		assertThatExceptionOfType(UnsupportedOperationException.class)
			.isThrownBy(() -> information.getCookies().clear());
	}

	@Test
	void withSessionIdWhenAuthoritiesProvidedThenCopiesAuthorities() {
		ReactiveSessionInformation information = new ReactiveSessionInformation("principal", "session-id",
				Instant.now(), Map.of("X-CSRF-TOKEN", "token"), Map.of("XSRF-TOKEN", "cookie-token"));

		ReactiveSessionInformation updated = information.withSessionId("new-session-id");

		assertThat(updated.getSessionId()).isEqualTo("new-session-id");
		assertThat(updated.getAuthorities()).containsOnly(entry("X-CSRF-TOKEN", "token"));
		assertThat(updated.getCookies()).containsOnly(entry("XSRF-TOKEN", "cookie-token"));
	}

}
