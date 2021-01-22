# Sign Maven Plugin 
[![Build](https://github.com/s4u/sign-maven-plugin/workflows/Build/badge.svg)](https://github.com/s4u/sign-maven-plugin/actions?query=workflow%3ABuild)
[![Reproducible Builds](https://img.shields.io/badge/Reproducible_Builds-ok-success?labelColor=1e5b96)](https://github.com/jvm-repo-rebuild/reproducible-central#org.simplify4u.plugins:sign-maven-plugin)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/org.simplify4u.plugins/sign-maven-plugin/badge.svg)](https://maven-badges.herokuapp.com/maven-central/org.simplify4u.plugins/sign-maven-plugin)

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=org.simplify4u.plugins%3Asign-maven-plugin&metric=alert_status)](https://sonarcloud.io/dashboard?id=org.simplify4u.plugins%3Asign-maven-plugin)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=org.simplify4u.plugins%3Asign-maven-plugin&metric=coverage)](https://sonarcloud.io/dashboard?id=org.simplify4u.plugins%3Asign-maven-plugin)
[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=org.simplify4u.plugins%3Asign-maven-plugin&metric=ncloc)](https://sonarcloud.io/dashboard?id=org.simplify4u.plugins%3Asign-maven-plugin)

Creates OpenPGP signatures for all of the project's artifacts
without any external software.

This plugin can replace **maven-gpg-plugin** in an easy way and provide new features.

# Feature 

 - all the signing operations are done using `Bouncy Castle`
 - support Maven `3.6` and is ready for next version `3.7/4.0` of Maven  with `Consumer POM`
 - support `subkey` for signing
 - easy to use on CI system, configuration can be provided by environment variables
 - key passphrase can be encrypted by standard Maven [Password Encryption](https://maven.apache.org/guides/mini/guide-encryption.html)

# Key prepare
    
Please look at our [tutorial](src/site/markdown/key-prepare.md)

# Usage
```xml

<plugins>
    <plugin>
        <groupId>org.simplify4u.plugins</groupId>
        <artifactId>sign-maven-plugin</artifactId>
        <version><!-- check releases page --></version>
        <executions>
            <execution>
                <goals>
                    <goal>sign</goal>
                </goals>
                <configuration>
                    <keyId><!-- key id in hex --></keyId>
                    <keyPass><!-- private key passphrase --></keyPass>
                    <keyFile><!-- private key file location --></keyFile>
                </configuration>
            </execution>
        </executions>
    </plugin>
    ...
</plugins>
```
# Testing latest snapshot version

Each build of current version is deployed to sonatype snapshots repository.
