/*
 * Copyright 2021 Slawomir Jaranowski
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.simplify4u.plugins.sign.utils;

import java.util.Optional;
import java.util.function.UnaryOperator;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;

@ExtendWith(MockitoExtension.class)
class EnvironmentTest {

    public static final String TEST_ENV_NAME = "TEST";

    @Mock
    private UnaryOperator<String> envGetter;

    @Mock
    private Logger logger;

    @InjectMocks
    private Environment environment;

    public static Stream<Arguments> shouldReadProperEnvironmentVariable() {
        return Stream.of(
                arguments(null, null),
                arguments("null", null),
                arguments("", null),
                arguments("  ", null),
                arguments(" trim value ", "trim value")
        );
    }

    @ParameterizedTest
    @MethodSource
    void shouldReadProperEnvironmentVariable(String envVariableValue, String result) {

        when(envGetter.apply(TEST_ENV_NAME)).thenReturn(envVariableValue);

        Optional<String> test = environment.getEnv(TEST_ENV_NAME);
        assertThat(test).isEqualTo(Optional.ofNullable(result));

        verify(envGetter).apply(TEST_ENV_NAME);
        verifyNoMoreInteractions(envGetter);
    }

    @Test
    void debugLogForEmptyValue() {

        when(envGetter.apply(TEST_ENV_NAME)).thenReturn(null);

        Optional<String> test = environment.getEnv(TEST_ENV_NAME);

        assertThat(test).isEmpty();

        verify(logger).debug("No {} set as environment variable", TEST_ENV_NAME);
        verifyNoMoreInteractions(logger);
    }

    @Test
    void debugLogForNotEmptyValue() {

        when(envGetter.apply(TEST_ENV_NAME)).thenReturn("Test");

        Optional<String> test = environment.getEnv(TEST_ENV_NAME);

        assertThat(test).hasValue("Test");

        verify(logger).debug("Retrieved {} configuration from environment variable", TEST_ENV_NAME);
        verifyNoMoreInteractions(logger);
    }

}
