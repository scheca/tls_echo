# Environment setup

## Certificate Authority

Create a CA that will sign the certificates of the client and server.

Generate the CA's key:

`$ openssl genrsa -des3 -out ca.key 4096`

Generate the CA certificate:

`$ openssl req -new -x509 -days 365 -key ca.key -out ca.crt`

---

## Client

Generate the client's key (it requires to enter a non-empty password):

`$ openssl genrsa -aes256 -out client_with_pass.key 4096`

Remove the PEM pass phrase from client's key:

`$ openssl rsa -in client_with_pass.key -out client.key`

Create a certificate request for the client:

`$ openssl req -new -key client.key -out client.csr`

Have our CA sign the client request to produce the client's certificate:

`$ openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out client.crt`

---

## Server

Generate the server's key (it requires to enter a non-empty password):

`$ openssl genrsa -aes256 -out server_with_pass.key 4096`

Remove the PEM pass phrase from server's key:

`$ openssl rsa -in server_with_pass.key -out server.key`

Create a certificate request for the server:

*When asked for the `Common Name`, enter `echo server`, as this is the entity that the client will connect to.*

`$ openssl req -new -key server.key -out server.csr`

Have our CA sign the server request to produce the server's certificate:

`$ openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out server.crt`
