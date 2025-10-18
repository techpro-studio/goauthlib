module github.com/techpro-studio/goauthlib

go 1.24.0

require (
	github.com/Timothylock/go-signin-with-apple v0.2.3
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/google/uuid v1.6.0
	github.com/michimani/gotwi v0.16.1
	github.com/techpro-studio/gohttplib v0.0.3
	github.com/techpro-studio/gomongo v0.0.9
	go.mongodb.org/mongo-driver/v2 v2.3.1
	golang.org/x/oauth2 v0.32.0
)

require github.com/golang/protobuf v1.5.2 // indirect

replace github.com/techpro-studio/gomongo => ../gomongo

require (
	github.com/golang-jwt/jwt/v5 v5.3.0 // indirect// indirect
	github.com/golang/snappy v1.0.0 // indirect
	github.com/johngb/langreg v0.0.0-20150123211413-5c6abc6d19d2 // indirect
	github.com/julienschmidt/httprouter v1.3.0 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/ttacon/builder v0.0.0-20170518171403-c099f663e1c2 // indirect
	github.com/ttacon/libphonenumber v1.2.1 // indirect
	github.com/xdg-go/pbkdf2 v1.0.0 // indirect
	github.com/xdg-go/scram v1.1.2 // indirect
	github.com/xdg-go/stringprep v1.0.4 // indirect
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78 // indirect
	golang.org/x/crypto v0.43.0 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/text v0.30.0 // indirect
	google.golang.org/appengine v1.6.8 // indirect
	google.golang.org/protobuf v1.36.10 // indirect
)
