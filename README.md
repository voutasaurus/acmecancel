# Installation

	go get -u github.com/voutasaurus/acmecancel

# Usage

Note: This tool only works with Let's Encrypt registration keys that are ECDSA P256. Registration keys of type RSA and ECDSA p384 are not supported.


	LE_KEY='{"ID":00000,"X":00000000,"Y":0000000000,"D":000000000}' acmecancel https://acme-v01.api.letsencrypt.org/acme/authz/XXXX


Your Let's Encrypt registration key and pending authz url should match the above pattern.

# Why did you write this

To the best of my knowledge there was not a standalone tool nor a subcommand of another tool to accomplish this.

# When will it support X?

PRs welcome. This is not a supported tool and I make no guarantees. You're liable for any damage you do by running this.
