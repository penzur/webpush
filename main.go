package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/handlers"
	"github.com/gorilla/pat"
)

var vapid *ecdsa.PrivateKey

type subscription struct {
	Endpoint string
	Keys     struct {
		P256dh string
		Auth   string
	}
}

var subscriptions = map[string]*subscription{}

func main() {
	// generate ecdh key pair
	var err error
	vapid, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	r := pat.New()
	r.StrictSlash(true)
	r.Get("/n/{id}", notify)
	r.Post("/", register)
	r.Get("/", index)

	port := ":" + os.Getenv("PORT")
	log.Fatal(
		http.ListenAndServe(
			port,
			handlers.CORS(
				handlers.AllowedOrigins([]string{"*"}),
				handlers.AllowedHeaders([]string{
					"X-Requested-With",
					"Content-Type",
					"Authorization",
				}),
				handlers.AllowedMethods([]string{
					"GET",
					"HEAD",
					"POST",
					"PUT",
					"OPTIONS",
				}),
			)(r),
		),
	)
}

func index(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, base64.RawURLEncoding.EncodeToString(publicKey(vapid)))
}

func register(w http.ResponseWriter, r *http.Request) {
	var sub subscription
	_ = json.NewDecoder(r.Body).Decode(&sub)

	log.Println("registered: ", sub.Keys.Auth)
	subscriptions[sub.Keys.Auth] = &sub

	fmt.Fprintln(w, sub.Keys.Auth+" registered with "+sub.Keys.P256dh)
}

func notify(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get(":id")
	msg := r.URL.Query().Get("msg")

	s, ok := subscriptions[id]
	if !ok {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	req, _ := http.NewRequest(
		http.MethodPost,
		s.Endpoint,
		bytes.NewBufferString(msg),
	)

	vh := vapidHeader(s)
	req.Header.Set("Authorization", vh)
	req.Header.Set("TTL", "3")
	req.Header.Set("Content-Encoding", "aes128gcm")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Fprintln(
		w,
		"Content: "+string(body)+", Status: "+resp.Status+" Vapid: "+vh,
	)
}

func vapidHeader(s *subscription) string {
	u, _ := url.Parse(s.Endpoint)
	k := base64.RawURLEncoding.EncodeToString(publicKey(vapid))
	t := vapidToken(fmt.Sprintf("%s://%s", u.Scheme, u.Host), "jupenz@gmail.com")
	return fmt.Sprintf("vapid t=%s,k=%s", t, k)
}

func vapidToken(endpoint, email string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodES256, &jwt.MapClaims{
		"aud": endpoint,
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"sub": fmt.Sprintf("mailto:%s", email),
	})

	str, err := token.SignedString(vapid)
	if err != nil {
		return ""
	}

	return str
}

func publicKey(prvk *ecdsa.PrivateKey) []byte {
	return elliptic.Marshal(
		prvk.Curve,
		prvk.PublicKey.X,
		prvk.PublicKey.Y,
	)
}
