# OpenPGP private key preparation

## Used software

For this tutorial I used `GnuPG` on `Mac OS`, but GnuPG on other system should be ok.
If you have special requirements on different operating system or different software,
please create issues or PR with clarification. 

```shell
gpg --version

gpg (GnuPG) 2.2.25
libgcrypt 1.8.7
```
## Creating a new private key

You can skip this point if you already have a private key.

Please run and follow instructions
```shell
gpg --full-gen-key
```

Now you can see your keys
```shell
gpg --list-secret-keys --keyid-format long
```
output should be similar to
```shell
------------------------------------------------
sec   rsa4096/0C5CEA1C96038404 2020-12-23 [SC]
      92BBFA4603B33BC283068CA40C5CEA1C96038404
uid                 [ultimate] Test Key <test@example.com>
ssb   rsa4096/3368CCB87F3FC7AE 2020-12-23 [E]

```
We have private key `sec` with keyId `0C5CEA1C96038404`, key has fingerprint `92BBFA4603B33BC283068CA40C5CEA1C96038404`

## Exporting private master key

For signing we need only key with flag `[S]`, so we export only one specific key 
(exclamation after `keyId` is important)

```shell
gpg --armor --export-secret-keys 0C5CEA1C96038404!
```

output of this command you can store in `~/.m2/sign-key.asc` or set as `SING_KEY` environment variable.

`sing-maven-plugin` by default will try load private key from this place.

## Creating a new subkey

`sing-maven-plugin` support signing by `subkey` instead of master key.

There are many articles explaining what is `subkeys` and those advantage and disadvantage, 
so please look for it yourself if you not familiar with `subkeys`

We have master key, so we need edit it

```shell
gpg --edit-key 0C5CEA1C96038404
```
at the `gpg>` prompt type: `addkey`, Choose `RSA (sign only)`

after it your keys should be look like

```shell
gpg --list-secret-keys --keyid-format long

------------------------------------------------
sec   rsa4096/0C5CEA1C96038404 2020-12-23 [SC]
      92BBFA4603B33BC283068CA40C5CEA1C96038404
uid                 [ultimate] Test Key <test@example.com>
ssb   rsa4096/3368CCB87F3FC7AE 2020-12-23 [E]
ssb   rsa4096/8F56B3C83F55E1A3 2020-12-23 [S]
```

We see a new sub key with id `8F56B3C83F55E1A3` and `[S]` flags.

So we can export this `subkey`  (exclamation after `keyId` is important)

```shell
gpg --armor --export-secret-subkeys 8F56B3C83F55E1A3!
```

Like for master key you can store your `subkey` in `~/.m2/sign-key.asc` or set as `SING_KEY` environment variable.


## Publishing public key 

Finally, you should publish your master public key to keys server network 
in order to make possibility to verify your signatures by other.

eg:
```shell
gpg --keyserver hkps://hkps.pool.sks-keyservers.net --send-key 0C5CEA1C96038404
```

