(def x 42)
x

(conj '[a b c] 'a)
(cons  'a '[a b c])
(vec '( a b c))

(defn kp-generator [length]
  (doto (java.security.KeyPairGenerator/getInstance "RSA")
    (.initialize length)))

(defn generate-keypair [length]
  (assert (>= length 512) "RSA Key must be at least 512 bits long.")
  (.generateKeyPair (kp-generator length)))

(def keypair (generate-keypair 512))
(def public-key (.getPublic keypair))

(defn decode64 [str]
  (.decode (java.util.Base64/getDecoder) str))

(defn encode64 [bytes]
  (.encodeToString (java.util.Base64/getEncoder) bytes))

  (defn encrypt [message public-key]
  "Perform RSA public key encryption of the given message string.
   Returns a Base64-encoded string of the encrypted data."
  (encode64
   (let [cipher (doto (javax.crypto.Cipher/getInstance "RSA/ECB/PKCS1Padding")
                  (.init javax.crypto.Cipher/ENCRYPT_MODE public-key))]
     (.doFinal cipher (.getBytes message)))))

(defn decrypt [message private-key]
  "Use an RSA private key to decrypt a Base64-encoded string
   of ciphertext."
  (let [cipher (doto (javax.crypto.Cipher/getInstance "RSA/ECB/PKCS1Padding")
                 (.init javax.crypto.Cipher/DECRYPT_MODE private-key))]
    (->> message
         decode64
         (.doFinal cipher)
         (map char)
         (apply str))))


(defn sign
  "RSA private key signing of a message. Takes message as string"
  [message private-key]
  (encode64
   (let [msg-data (.getBytes message)
         sig (doto (java.security.Signature/getInstance "SHA256withRSA")
               (.initSign private-key (java.security.SecureRandom.))
               (.update msg-data))]
     (.sign sig))))

(defn verify [encoded-sig message public-key]
  "RSA public key verification of a Base64-encoded signature and an
   assumed source message. Returns true/false if signature is valid."
  (let [msg-data (.getBytes message)
        signature (decode64 encoded-sig)
        sig (doto (java.security.Signature/getInstance "SHA256withRSA")
              (.initVerify public-key)
              (.update msg-data))]
    (.verify sig signature)))

(defn der-string->pub-key [string]
  "Generate an RSA public key from a DER-encoded Base64 string.
   Some systems like to line-wrap these at 64 characters, so we
   have to get rid of any newlines before decoding."
  (let [non-wrapped (clojure.string/replace string #"\n" "")
        key-bytes (decode64 non-wrapped)
        spec (java.security.spec.X509EncodedKeySpec. key-bytes)
        key-factory (java.security.KeyFactory/getInstance "RSA")]
    (.generatePublic key-factory spec)))

(defn public-key->der-string [key]
  "Generate DER-formatted string for a public key."
  (-> key
      .getEncoded
      encode64
      (clojure.string/replace #"\n" "")))

(defn der-string->private-key [string]
  (.generatePrivate (java.security.KeyFactory/getInstance "RSA")
                    (java.security.spec.PKCS8EncodedKeySpec.
                     (decode64 (.getBytes string)))))

(defn private-key->der-string [pk]
  (-> pk
      .getEncoded
      java.security.spec.PKCS8EncodedKeySpec.
      .getEncoded
      encode64))

(defproject block-chain "0.2.0"
  :dependencies [[org.clojure/clojure "1.8.0"]
                 [org.bouncycastle/bcpkix-jdk15on "1.53"]])