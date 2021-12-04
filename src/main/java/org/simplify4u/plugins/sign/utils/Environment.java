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
import javax.inject.Named;
import javax.inject.Singleton;

import lombok.extern.slf4j.Slf4j;

/**
 * Environment variable support.
 */
@Slf4j
@Named
@Singleton
public class Environment {

    /**
     * Function for read environment variable.
     */
    private final UnaryOperator<String> environmentGetter;

    /**
     * Default class with {@link System#getenv(String)} as variable provider.
     */
    public Environment() {
        this(System::getenv);
    }

    /**
     * For testing purpose we can provide our function or mock for reading environment variable.
     *
     * @param environmentGetter a environment variable provider.
     */
    Environment(UnaryOperator<String> environmentGetter) {
        this.environmentGetter = environmentGetter;
    }

    /**
     * Read environment variable and filter by "null" string - this value is set be invoker-maven-plugin.
     * <p>
     * TODO - remove workaround after fix and release https://issues.apache.org/jira/browse/MINVOKER-273
     *
     * @param environmentName a environment variable name
     *
     * @return content of environment variable or empty if not exist.
     */
    public Optional<String> getEnv(String environmentName) {
        Optional<String> returnValue = Optional.ofNullable(environmentGetter.apply(environmentName))
                .map(String::trim)
                .filter(s -> !"null".equals(s))
                .filter(s -> !s.isEmpty());

        if (returnValue.isPresent()) {
            LOGGER.debug("Retrieved {} configuration from environment variable", environmentName);
        } else {
            LOGGER.debug("No {} set as environment variable", environmentName);
        }

        return returnValue;
    }
}
