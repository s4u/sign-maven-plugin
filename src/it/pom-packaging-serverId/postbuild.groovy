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
import java.nio.file.Files

def basedirPath = basedir.toPath()

assert Files.exists(basedirPath.resolve("target").resolve("pom-packaging-serverId-1.1.1.pom.asc"))

def mod1TargetPath = basedirPath.resolve("mod1").resolve("target")
assert Files.exists(mod1TargetPath.resolve("pom-packaging-serverId-mod1-1.1.1.pom.asc"))
assert Files.exists(mod1TargetPath.resolve("pom-packaging-serverId-mod1-1.1.1.jar.asc"))

def mod2TargetPath = basedirPath.resolve("mod2").resolve("target")
assert Files.exists(mod2TargetPath.resolve("pom-packaging-serverId-mod2-1.1.1.pom.asc"))
assert Files.exists(mod2TargetPath.resolve("pom-packaging-serverId-mod2-1.1.1.jar.asc"))
