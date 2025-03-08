# Valid Access Token

## JWT

```jwt
eyJ0eXAiOiJhdCtqd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6Ijc3ZTFiOTBhNDRlN2UwZTQ0ZGJkZjY4NDNkNTJiZWQ1In0.eyJpc3MiOiJpc3N1ZXIiLCJhdWQiOiJhdWRpZW5jZSIsInN1YiI6IjViZTg2MzU5MDczYzQzNGJhZDJkYTM5MzIyMjJkYWJlIiwiY2xpZW50X2lkIjoiY2xpZW50X2FwcCIsImV4cCI6MTc0MTQxNjM5NywiaWF0IjoxNzQxNDEyNzk3LCJqdGkiOiJjZjRkYWYzZThlYjY5MTEwYzZhNWYyNWFkODZmZmVjZSIsInNjb3BlIjoicmVhZCB3cml0ZSBkZWxldGUifQ.c6KmZ7E7ESk_wAEgFG-JDkQXzPJluNjTwo2XMhR5YBgd2EXEKKFBR_gORQNBv1HgVg8dB05qG9N-kyUI__tG1A
```

### Header

```json
{
  "typ": "at+jwt",
  "alg": "ES256",
  "kid": "77e1b90a44e7e0e44dbdf6843d52bed5"
}
```

### Payload

```json
{
  "iss": "issuer",
  "aud": "audience",
  "sub": "5be86359073c434bad2da3932222dabe",
  "client_id": "client_app",
  "exp": 1741416397,
  "iat": 1741412797,
  "jti": "cf4daf3e8eb69110c6a5f25ad86ffece",
  "scope": "read write delete"
}
```

### Signing Key

- [access_token_jwk.private.json](./access_token_jwk.private.json)
