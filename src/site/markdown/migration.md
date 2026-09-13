# Migration to maven-gpg-plugin

`sign-maven-plugin` is retired. Everything it was created for is now available in
[Apache Maven GPG Plugin](https://maven.apache.org/plugins/maven-gpg-plugin/):

- signing by the `Bouncy Castle` Java library, so no `gpg` executable is required
- key configuration provided by environment variables, which makes CI usage easy
- support for Maven `4`

See [Sign using BC signer](https://maven.apache.org/plugins/maven-gpg-plugin/examples/deploy-signed-artifacts.html#sign-using-bc-signer)
in the GPG Plugin documentation.

Maintaining a second plugin with the same feature set is no longer justified, so please migrate.

## Your key does not change

Both plugins consume the very same thing: an OpenPGP transferable secret key, as produced by

```shell
gpg --armor --export-secret-keys 0C5CEA1C96038404!
```

So whatever you prepared by following
[Open PGP / GPG private key preparation](./key-prepare.html) keeps working as is - the file in
`~/.m2/sign-key.asc` and the value in your CI secret do not have to be regenerated.
Signing with an exported **subkey** works as well.

Only the plugin declaration and the names of the configuration options change.

## Configuration mapping

| `sign-maven-plugin`                                   | `maven-gpg-plugin`                                              | Note                                                        |
|-------------------------------------------------------|-----------------------------------------------------------------|-------------------------------------------------------------|
| -                                                     | `signer` / `gpg.signer`                                         | must be set to `bc`, the default is the `gpg` executable    |
| `keyFile` / `sign.keyFile`<br/>(`~/.m2/sign-key.asc`) | `keyFilePath` / `gpg.keyFilePath`<br/>(`maven-signing-key.key`) | a relative path is resolved against the user home directory |
| `SIGN_KEY` env - key **content**                      | `MAVEN_GPG_KEY` env - key **content**                           | variable name configurable by `keyEnvName`                  |
| `keyId` / `sign.keyId` - key id                       | `keyFingerprint` / `gpg.keyFingerprint` - **fingerprint**       | see *Key id to fingerprint* below                           |
| `SIGN_KEY_ID` env                                     | `MAVEN_GPG_KEY_FINGERPRINT` env                                 | variable name configurable by `keyFingerprintEnvName`       |
| `keyPass` / `sign.keyPass`                            | `passphrase` / `gpg.passphrase`                                 | discouraged, rejected when `bestPractices` is `true`        |
| `SIGN_KEY_PASS` env                                   | `MAVEN_GPG_PASSPHRASE` env                                      | the recommended way, configurable by `passphraseEnvName`    |
| `serverId` / `sign.serverId`                          | `passphraseServerId` / `gpg.passphraseServerId`                 | **passphrase only**, see *Key in settings.xml*              |
| `skip` / `sign.skip`                                  | `skip` / `gpg.skip`                                             |                                                             |
| `skipNoKey` / `sign.skipNoKey` (`true`)               | -                                                               | no direct equivalent, see *Missing key* below               |
| `excludes`                                            | `excludes`                                                      | GPG Plugin also excludes `sigstore` files by default        |
| `sign` goal, `verify` phase                           | `sign` goal, `verify` phase                                     | the binding does not change                                 |

## Key in an environment variable

This is the recommended setup for a CI system, and the closest to the `sign-maven-plugin` one.
Rename the three variables in your CI configuration:

| Before          | After                        |
|-----------------|------------------------------|
| `SIGN_KEY`      | `MAVEN_GPG_KEY`              |
| `SIGN_KEY_PASS` | `MAVEN_GPG_PASSPHRASE`       |
| `SIGN_KEY_ID`   | `MAVEN_GPG_KEY_FINGERPRINT`  |

and replace the plugin declaration:

```xml

<plugins>
    <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-gpg-plugin</artifactId>
        <version>3.2.8</version>
        <configuration>
            <signer>bc</signer>
        </configuration>
        <executions>
            <execution>
                <goals>
                    <goal>sign</goal>
                </goals>
            </execution>
        </executions>
    </plugin>
    ...
</plugins>
```

## Key in a file

`sign-maven-plugin` looked for `~/.m2/sign-key.asc` by default. The GPG Plugin resolves a relative
`keyFilePath` against the user home directory, so point it at the same file:

```xml

<configuration>
    <signer>bc</signer>
    <keyFilePath>.m2/sign-key.asc</keyFilePath>
</configuration>
```

The passphrase should still come from the `MAVEN_GPG_PASSPHRASE` environment variable.

## Key in settings.xml

There is **no full equivalent**. `sign-maven-plugin` read the key id, the key file location and the
passphrase from a single `server` entry; the GPG Plugin uses `passphraseServerId` for the
**passphrase only**:

```xml

<settings>
    ...
    <servers>
        <server>
            <id>sign-key-id</id>
            <passphrase><!-- private key passphrase, can be encrypted --></passphrase>
        </server>
    </servers>
</settings>
```

The key itself has to be provided by `keyFilePath` or by the `MAVEN_GPG_KEY` environment variable.

Note that `passphraseServerId` is discouraged by the GPG Plugin and is rejected when
`bestPractices` is set to `true` - an environment variable is the recommended way.

## Key id to fingerprint

`sign-maven-plugin` selected the key by its **key id**, the GPG Plugin selects it by the full
**fingerprint**. You only need it when the provided key material contains more than one key -
otherwise drop the option and the first key will be used.

```shell
gpg --list-secret-keys --keyid-format long --with-subkey-fingerprint
```

```shell
------------------------------------------------
sec   rsa4096/0C5CEA1C96038404 2020-12-23 [SC]
      92BBFA4603B33BC283068CA40C5CEA1C96038404
uid                 [ultimate] Test Key <test@example.com>
ssb   rsa4096/8F56B3C83F55E1A3 2020-12-23 [S]
      A1B2C3D4E5F60718293A4B5C8F56B3C83F55E1A3
```

The line below each key is its fingerprint, and it already ends with the key id you used before.
So `keyId` `8F56B3C83F55E1A3` becomes `keyFingerprint` `A1B2C3D4E5F60718293A4B5C8F56B3C83F55E1A3`.

## Missing key

This is the one behaviour change that is likely to break a build.

`sign-maven-plugin` skipped signing when no key was found, so the same `pom.xml` worked on a
developer workstation without a key and on a release machine with one. The GPG Plugin has no
`skipNoKey` counterpart and fails the build:

```text
[ERROR] Failed to execute goal org.apache.maven.plugins:maven-gpg-plugin:3.2.8:sign (default)
        on project ... : Secret key not found
```

You can get the old behaviour back with a profile that detects the absence of the key and sets
`gpg.skip` - no change to the way you invoke Maven:

```xml

<profiles>
    <profile>
        <!-- skip gpg executing - if key is not available -->
        <id>skip-gpg</id>
        <activation>
            <property>
                <name>!env.MAVEN_GPG_KEY</name>
            </property>
            <file>
                <missing>${user.home}/.m2/sign-key.asc</missing>
            </file>
        </activation>
        <properties>
            <gpg.skip>true</gpg.skip>
        </properties>
    </profile>
</profiles>
```

Both activation conditions have to hold, so signing is skipped only when the key is available
neither in the environment variable nor in the file - exactly what `skipNoKey` did.

**NOTICE** - the file has to be named twice, and in two different ways: `keyFilePath` resolves a
relative path against the user home directory, while the `missing` activation needs a full path.
Keep the two in sync.

Alternatively declare the signing execution in a profile activated only when you publish, or keep
the plugin in the main build and pass `-Dgpg.skip=true` where no key is available.
