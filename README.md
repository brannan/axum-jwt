# JWT Example From Axum Examples on Github

Quick instructions:
```bash
#get an authorization token:

curl -s -w '\n' -H 'Content-Type: application/json' \
    -d '{"client_id":"foo","client_secret":"bar"}' \
    http://localhost:3456/authorize

# visit the protected area using the authorized token

curl -s  -w '\n'  -H 'Content-Type: application/json' \
    -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJleHAiOjIwMDAwMDAwMDB9.uR_4i-0-xf5N3ygVI9AT6XEelatzbuVRFnpBLKao6rs' \
    http://localhost:3456/protected

# try to visit the protected area using an invalid token

curl -I -H 'Content-Type: application/json' \
    -H 'Authorization: Bearer blahblahblah' http://localhost:3456/protected

# Not silent
curl -I -H 'Content-Type: application/json' -H 'Authorization: Bearer blahblahblah' http://localhost:3456/protected

# try to visit the protected area using no token

curl -I -H 'Content-Type: application/json' http://localhost:3456/protected
```

## TODO

The token is extracted in an extractor. Move extraction to context middleware that
never errors. Then make mw_auth middleware that can be required by routes needing auth
