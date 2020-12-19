# Sign Maven Plugin 
[![Build](https://github.com/s4u/sign-maven-plugin/workflows/Build/badge.svg)](https://github.com/s4u/sign-maven-plugin/actions?query=workflow%3ABuild)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=org.simplify4u.plugins%3Asign-maven-plugin&metric=alert_status)](https://sonarcloud.io/dashboard?id=org.simplify4u.plugins%3Asign-maven-plugin)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=org.simplify4u.plugins%3Asign-maven-plugin&metric=coverage)](https://sonarcloud.io/dashboard?id=org.simplify4u.plugins%3Asign-maven-plugin)
[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=org.simplify4u.plugins%3Asign-maven-plugin&metric=ncloc)](https://sonarcloud.io/dashboard?id=org.simplify4u.plugins%3Asign-maven-plugin)

Creates OpenPGP signatures for all of the project's artifacts
without any external software.

# Feature 

 - all the signing operations are done using `Bouncy Castle`
 - support Maven `3.6` and is ready for next version `3.7/4.0` of Maven  with `Consumer POM`
 - easy to use on CI system, configuration can be provided by environment variables 

# Key prepare

    gpg --full-generate-key
    gpg --list-secret-keys
    gpg --armor --export-secret-keys
    gpg --armor --export 

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

Each build of current version of is deployed to sonatype snapshots repository.
