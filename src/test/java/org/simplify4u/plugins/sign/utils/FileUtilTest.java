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

import java.io.File;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class FileUtilTest {

    private static String userHome = System.getProperty("user.home");

    public static Stream<Arguments> shouldDetectUserHomeInPath() {
        return Stream.of(
                arguments(f("test.key"), f("test.key")),
                arguments(f("/test.key"), f("/test.key")),
                arguments(f("/abc/test.key"), f("/abc/test.key")),
                arguments(f("~test.key"), f("~test.key")),
                arguments(f("~/test.key"), f(userHome, "test.key")),
                arguments(f("~/abc/test.key"), f(userHome, "abc/test.key"))
        );
    }

    private static File f(String fineName) {
        return new File(fineName);
    }

    private static File f(String parent, String fineName) {
        return new File(parent, fineName);
    }

    @ParameterizedTest
    @MethodSource
    void shouldDetectUserHomeInPath(File in, File out) {

        File file = FileUtil.calculateWithUserHome(in);
        assertThat(file).isEqualTo(out);
    }
}
