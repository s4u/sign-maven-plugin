/*
 * Copyright 2020 Markus Karg
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

def target = basedir.toPath().resolve( "target" )
def pomSignature = target.resolve( "standard-packaging-1.1.1.pom.asc" )
def jarSignature = target.resolve( "standard-packaging-1.1.1.jar.asc" )
def jarSha512 = target.resolve( "standard-packaging-1.1.1.jar.sha512" )
def jarSha512Signature = target.resolve( "standard-packaging-1.1.1.jar.sha512.asc" )
def datSignature = target.resolve( "standard-packaging-1.1.1.dat.asc" )
def c1DatSignature = target.resolve( "standard-packaging-1.1.1-c1.dat.asc" )

assert Files.exists( pomSignature )
assert Files.exists( jarSignature )
assert Files.exists( jarSha512 )
assert !Files.exists( jarSha512Signature )
assert Files.exists( datSignature )
assert Files.exists( c1DatSignature )

