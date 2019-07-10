package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/handlers"
	"github.com/gorilla/pat"
	"golang.org/x/crypto/hkdf"
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

func notify(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get(":id")
	msg := r.URL.Query().Get("msg")

	s, ok := subscriptions[id]
	if !ok {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	pl, _ := encrypt(msg, s.Keys.P256dh, s.Keys.Auth)
	req, _ := http.NewRequest(
		http.MethodPost,
		s.Endpoint,
		pl,
	)

	vh := vapidHeader(s)

	req.Header.Set("Authorization", vh)
	req.Header.Set("TTL", "60")
	req.Header.Set("Content-Encoding", "aes128gcm")
	req.Header.Set("Content-Type", "application/octet-stream")

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

func encrypt(msg, public, secret string) (*bytes.Buffer, int) {
	curve := elliptic.P256()
	// generate private key
	private, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		log.Println(err.Error())
		return nil, 0
	}

	// public key from private
	localPublicBytes := getPublicKey(private)

	// unmarshal public key
	publicBytes, err := base64.RawURLEncoding.DecodeString(public)
	if err != nil {
		log.Println(err.Error())
		return nil, 0
	}

	// unmarshall secret
	secretBytes, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil {
		log.Println(err.Error())
		return nil, 0
	}

	// derived from public and our private
	x, y := elliptic.Unmarshal(curve, publicBytes)
	derivedSecret, _ := curve.ScalarMult(x, y, private.D.Bytes())
	derivedSecretBytes := derivedSecret.Bytes()

	// prk key
	keyBytes := hkdf.Extract(sha256.New, secretBytes, derivedSecretBytes)

	// key info
	keyInfo := bytes.NewBuffer([]byte{})
	keyInfo.WriteString("Webpush: info\x00")
	keyInfo.Write(publicBytes)
	keyInfo.Write(localPublicBytes)
	keyInfo.WriteByte(0x01)

	// ikm
	ikm := hkdf.Expand(sha256.New, keyBytes, keyInfo.Bytes())
	ikmBytes := make([]byte, 32)
	_, _ = io.ReadFull(ikm, ikmBytes)

	// generate salt
	saltBytes := make([]byte, 16)
	_, _ = io.ReadFull(rand.Reader, saltBytes)

	// prk
	prkBytes := hkdf.Extract(sha256.New, saltBytes, ikmBytes)

	// cek info
	cekInfo := bytes.NewBuffer([]byte{})
	cekInfo.WriteString("Content-Encoding: aes128gcm\x00")
	cekInfo.WriteByte(0x01)

	// cek
	cek := hkdf.Expand(sha256.New, prkBytes, cekInfo.Bytes())
	cekBytes := make([]byte, 16)
	_, _ = io.ReadFull(cek, cekBytes)

	// nonce info
	nonceInfo := bytes.NewBuffer([]byte{})
	nonceInfo.WriteString("Content-Encoding: nonce\x00")
	nonceInfo.WriteByte(0x01)

	// nonce
	nonceReader := hkdf.Expand(sha256.New, prkBytes, nonceInfo.Bytes())
	nonceBytes := make([]byte, 12)
	_, _ = io.ReadFull(nonceReader, nonceBytes)

	// start encryption
	block, err := aes.NewCipher(cekBytes)
	if err != nil {
		log.Println(err.Error())
		return nil, 0
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Println(err.Error())
		return nil, 0
	}

	// msg buffer
	msgBuff := bytes.NewBuffer([]byte{})
	msgBuff.WriteString(msg)
	msgBuff.WriteByte(0x02)

	// header
	headerBytes := make([]byte, 21+65)
	copy(headerBytes[0:], saltBytes)
	copy(headerBytes[16:], uintBytes(uint32(4096)))
	headerBytes[20] = byte(65)
	copy(headerBytes[21:], publicBytes)

	// paddding
	padl := 3994 - msgBuff.Len()
	padBytes := make([]byte, padl)
	msgBuff.Write(padBytes)

	// record and record size
	record := aesgcm.Seal([]byte{}, nonceBytes, msgBuff.Bytes(), nil)

	payload := bytes.NewBuffer([]byte{})
	payload.Write(headerBytes)
	payload.Write(record)

	return payload, payload.Len()
}

func uintBytes(n uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, n)
	return b
}

func index(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, base64.RawURLEncoding.EncodeToString(getPublicKey(vapid)))
}

func register(w http.ResponseWriter, r *http.Request) {
	var sub subscription
	_ = json.NewDecoder(r.Body).Decode(&sub)

	log.Println("registered: ", sub.Keys.Auth)
	subscriptions[sub.Keys.Auth] = &sub

	fmt.Fprintln(w, sub.Keys.Auth+" registered with "+sub.Keys.P256dh)
}

func getPublicKey(prvk *ecdsa.PrivateKey) []byte {
	return elliptic.Marshal(
		prvk.Curve,
		prvk.PublicKey.X,
		prvk.PublicKey.Y,
	)
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

func vapidHeader(s *subscription) string {
	u, _ := url.Parse(s.Endpoint)
	k := base64.RawURLEncoding.EncodeToString(getPublicKey(vapid))
	t := vapidToken(
		fmt.Sprintf(
			"%s://%s",
			u.Scheme,
			u.Host,
		),
		"jupenz@gmail.com",
	)
	return fmt.Sprintf("vapid t=%s,k=%s", t, k)
}
