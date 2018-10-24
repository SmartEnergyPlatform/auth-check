# Auth Check

## Endpoints:
- /auth - Zugriffsschutz:
wird vom Kong Middleman Plugin durch POST Request aufgrufen, ob der Request weitergeleitete werden soll oder blockiert werden soll
gibt entweder 200 oder 401 als Antwort 
TODO: error messages
TODO: nur public keycloak endpoints offen lassen, nicht alles mit pfad /auth

public APIs:
- /auth/realms/master/.well-known/openid-configuration - Discovery, enthält alle Endpoints
- /auth/realms/master/protocol/openid-connect/auth - Authentication Endpoint für OAuth Code Flow
- /auth/realms/master/protocol/openid-connect/token - Token Endpoint
- /auth/realms/master/protocol/openid-connect/userinfo - User Info Endpoint 

# Build
```
docker build -t auth .
```

# Run
- you have to set the env variables keycloak_url and ladon_url
- it is very important to set keycloak to the same domain which is used to query the tokens
- and not to use the internal container name because then there is a problem with the token validation and the token issuer 
- for local testing you have to change the host file because there you cannot use one domain by default 
- see here for future updates about the issuer problem:
https://issues.jboss.org/browse/KEYCLOAK-6073
- if its solved, you can use the internal keycloak 

```shell
docker run -e "keycloak_url=http://keycloak:8080" -e "ladon_url=http://ladon:8080"-p 8080:8080 auth
```

# User Authentication
- the user gets authenticated by validating the access token by requesting KeyCloak
- requirement: client secret and credentials hardcoded 

## Token Validation
- Validation points:
- Expiration
- Issuer
- Verfication of the signature using the public keys from keycloak

# User Authorization
- the user gets authorized by getting his role from the validated token and checking his permission regarding his actions by asking an [external service](https://gitlab.wifa.uni-leipzig.de/fg-seits/auth-ladon)
- Authorization by pre created policies
- Role and endpoint relation, e.g. admin can post to an special endpoint
- if no policy is found the request gets default denied
- every request has to be authenicated, except of the OAuth/OIDC requests 