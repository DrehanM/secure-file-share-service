package proj2

// CS 161 Project 2 Spring 2020
// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder. We will be very upset.

import (
	// You neet to add with
	// go get github.com/cs161-staff/userlib
	"github.com/cs161-staff/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging, etc...
	"encoding/hex"

	// UUIDs are generated right based on the cryptographic PRNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys.
	"strings"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	_ "strconv"
	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

const (
	SALT_BYTES            = 16
	USER_STRUCT_KEY_BYTES = 32
	USER_STRUCT_IV_BYTES  = 16
)

// This serves two purposes:
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.
// Of course, this function can be deleted.
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

func addSignatureToCipher(signature []byte, cipher []byte) (data []byte) {
	data = append(signature, cipher...)
	return data
}

func signMessage(cipher []byte, message []byte, key userlib.DSSignKey) (data []byte, err error) {
	signature, err := userlib.DSSign(key, message)
	if err != nil {
		return nil, err
	}
	data = addSignatureToCipher(signature, cipher)
	return data, nil
}

func hash(data []byte) (hash []byte, err error) {
	hash, err = userlib.HMACEval(make([]byte, 16), data)
	if err != nil {
		return nil, err
	}
	return hash, nil
}

func makeDataStoreKey(keyData string) (key uuid.UUID, err error) {
	var keyDatabytes []byte = []byte(keyData)
	hash, err := hash(keyDatabytes)
	if err != nil {
		return uuid.Nil, err
	}
	key = bytesToUUID(hash)
	return key, nil
}

// The structure definition for a user record
type User struct {
	Username   string
	PrivateKey userlib.PrivateKeyType
	PublicKey  userlib.PublicKeyType
	SignMap    map[string]userlib.DSSignKey
	OwnedFiles []string

	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the password has strong entropy, EXCEPT
// the attackers may possess a precomputed tables containing
// hashes of common passwords downloaded from the internet.
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User

	userdata.OwnedFiles = []string{}
	userdata.SignMap = map[string]userlib.DSSignKey{}
	userdata.Username = username

	userdata.PublicKey, userdata.PrivateKey, err = userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}

	//generate salt for password
	var salt []byte = userlib.RandomBytes(SALT_BYTES)

	//generate key to be used for symmetric encryption of userdata struct
	var symkey []byte = userlib.Argon2Key([]byte(password), salt, USER_STRUCT_KEY_BYTES)

	var IV []byte = userlib.RandomBytes(USER_STRUCT_IV_BYTES)

	//convert userdata to string
	msg, err := json.Marshal(userdata)
	if err != nil {
		return nil, err
	}

	//generate ciphertext
	var cipher []byte = userlib.SymEnc(symkey, IV, msg)

	//generate HMAC signature
	signature, err := userlib.HMACEval(symkey, msg)
	if err != nil {
		return nil, err
	}

	//append ciphertext to signature
	var dataToStore []byte = addSignatureToCipher(signature, cipher)

	key, err := makeDataStoreKey("account_info" + userdata.Username)
	if err != nil {
		return nil, err
	}

	saltkey, err := makeDataStoreKey("salt" + userdata.Username)
	if err != nil {
		return nil, err
	}

	userlib.DebugMsg("%s", string(msg))

	//Update keyStore
	userlib.KeystoreSet(userdata.Username, userdata.PublicKey)

	//Update dataStore
	userlib.DatastoreSet(key, dataToStore)
	userlib.DatastoreSet(saltkey, salt)

	return &userdata, nil
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User

	key, err := makeDataStoreKey("account_info" + username)
	if err != nil {
		return nil, err
	}
	data, exists := userlib.DatastoreGet(key)
	if !exists {
		userlib.DebugMsg("u:" + username + " p:" + password + "does not exist")
		return nil, errors.New("username not found error")
	}

	saltkey, err := makeDataStoreKey("salt" + username)
	if err != nil {
		return nil, err
	}
	salt, exists := userlib.DatastoreGet(saltkey)
	if !exists {
		userlib.DebugMsg("u:" + username + "salt does not exist")
		return nil, errors.New("salt not found error")
	}
	var symkey []byte = userlib.Argon2Key([]byte(password), salt, USER_STRUCT_KEY_BYTES)

	var decrypted []byte = userlib.SymDec(symkey, data[64:])

	hmac, err := userlib.HMACEval(symkey, decrypted)
	if err != nil {
		return nil, err
	}

	var hmacOld []byte = data[:64]

	if !userlib.HMACEqual(hmac, hmacOld) {
		return nil, errors.New("MAC doesn't match, user data has been tampered with")
	}

	json.Unmarshal(decrypted, &userdata)

	return &userdata, nil
}

// This stores a file in the datastore.
//
// The plaintext of the filename + the plaintext and length of the filename
// should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {

	//TODO: This is a toy implementation.
	UUID, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	packaged_data, _ := json.Marshal(data)
	userlib.DatastoreSet(UUID, packaged_data)
	//End of toy implementation

	return
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	return
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {

	//TODO: This is a toy implementation.
	UUID, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	packaged_data, ok := userlib.DatastoreGet(UUID)
	if !ok {
		return nil, errors.New(strings.ToTitle("File not found!"))
	}
	json.Unmarshal(packaged_data, &data)
	return data, nil
	//End of toy implementation

	return
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
func (userdata *User) ShareFile(filename string, recipient string) (
	magic_string string, err error) {

	return
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {
	return nil
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {
	return
}
