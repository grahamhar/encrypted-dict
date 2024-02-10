# NOTICE

This project is no longer maintained or supported use it at your own risk.

# encrypted-dict

![](http://pepy.tech/badge/encrypteddict)

Encrypt values in dict so that the dict remains readable in plain text except for the encrypted sections,
it's main use is for when outputing dicts to be stored on disk as yaml or json.

## Setup

pygpgme requires libgpgme11-dev on Ubuntu and on Mac OSX (via brew) you need gpgme and libgpg-error


Inspired by:

[hiera-eyaml](https://github.com/TomPoulton/hiera-eyaml) and [hiera-eyaml-gpg](https://github.com/sihil/hiera-eyaml-gpg)
