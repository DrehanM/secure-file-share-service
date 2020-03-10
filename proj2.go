package proj2

// CS 161 Project 2 Spring 2020
// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder. We will be very upset.

import (
	// You neet to add with
	// go get github.com/cs161-staff/userlib
	"fmt"

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
	BLOCK_STRUCT_IV_BYTES = 16
	RSA_SIGN_BYTES        = 256

	MAX_BLOCK_SIZE = 256

	ACCOUNT_INFO_PREFIX    = "account_info"
	SALT_PREFIX            = "salt"
	BLOCK_PREFIX           = "block"
	METADATA_PREFIX        = "metadata"
	ACCESS_TOKEN_PREFIX    = "access_token"
	SIGNING_TOKEN_PREFIX   = "signing_token"
	FILE_INFO_TOKEN_PREFIX = "fileid_token"
	FILEKEY_PREFIX         = "filekey"
	FILE_DS_PREFIX         = "file digisig"
	USER_DS_PREFIX         = "user digisig"
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
		fmt.Printf("%s\n", err)
		return nil, err
	}
	data = addSignatureToCipher(signature, cipher)
	return data, nil
}

func hash(data []byte) (hash []byte, err error) {
	hash, err = userlib.HMACEval(make([]byte, 16), data)
	if err != nil {
		fmt.Printf("%s\n", err)
		return nil, err
	}
	return hash, nil
}

func makeDataStoreKey(keyData string) (key uuid.UUID, err error) {
	var keyDatabytes []byte = []byte(keyData)
	hash, err := hash(keyDatabytes)
	if err != nil {
		fmt.Printf("%s\n", err)
		return uuid.Nil, err
	}
	key = bytesToUUID(hash)
	return key, nil
}

func makeDataStoreKeyAll(parts ...string) (key uuid.UUID, err error) {
	var concat string

	for _, part := range parts {
		hash, _ := makeDataStoreKey(part)
		concat += strings.ReplaceAll(hash.String(), "-", "")
	}

	return makeDataStoreKey(concat)
}

func encryptAndSign(contents []byte, publicKey userlib.PKEEncKey, signingKey userlib.DSSignKey) ([]byte, error) {
	IV := userlib.RandomBytes(BLOCK_STRUCT_IV_BYTES)
	message := append(IV, contents...)
	ciphertext, err := userlib.PKEEnc(publicKey, message)

	if err != nil {
		fmt.Printf("%d\n", len(message))
		fmt.Printf("%s\n", err)
		return nil, err
	}
	record, err := signMessage(ciphertext, message, signingKey)

	if err != nil {
		fmt.Printf("%s\n", err)
		return nil, err
	}

	return record, nil
}

func decryptAndVerify(contents []byte, v interface{}, privateKey userlib.PKEDecKey, verifyKey userlib.DSVerifyKey) (err error) {
	fmt.Printf("%08b\n", contents)
	signature := contents[:RSA_SIGN_BYTES]
	ciphertext := contents[:RSA_SIGN_BYTES]
	message, _ := userlib.PKEDec(privateKey, ciphertext)

	err = userlib.DSVerify(verifyKey, message, signature)
	if err != nil {
		fmt.Printf("%s\n", err)
		return err
	}

	err = json.Unmarshal(message[BLOCK_STRUCT_IV_BYTES:], &v)
	if err != nil {
		userlib.DebugMsg("Unmarshal failed")
		return err
	}
	return nil
}

func min(a int, b int) (retval int) {
	if a < b {
		return a
	}
	return b
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

type Sharetree struct {
	Parent   string
	Children []string
}

type Block struct {
	BlockID  uint32
	Contents []byte
	Next     *Block
}

type Metadata struct {
	Owner      string
	Filename   string
	BlockCount uint32
	Head       *Block
	Members    []string
	Sharetree  []Sharetree
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
		fmt.Printf("%s\n", err)
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
		fmt.Printf("%s\n", err)
		return nil, err
	}

	//generate ciphertext
	var cipher []byte = userlib.SymEnc(symkey, IV, msg)

	//generate HMAC signature
	signature, err := userlib.HMACEval(symkey, msg)
	if err != nil {
		fmt.Printf("%s\n", err)
		return nil, err
	}

	//append ciphertext to signature
	var dataToStore []byte = addSignatureToCipher(signature, cipher)

	//construct key user struct in dataStore
	key, err := makeDataStoreKeyAll(ACCOUNT_INFO_PREFIX, userdata.Username)
	if err != nil {
		fmt.Printf("%s\n", err)
		return nil, err
	}

	//construct key for salt in dataStore
	saltkey, err := makeDataStoreKeyAll(SALT_PREFIX, userdata.Username)
	if err != nil {
		fmt.Printf("%s\n", err)
		return nil, err
	}

	//userlib.DebugMsg("%s", string(msg))

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

	key, err := makeDataStoreKeyAll(ACCOUNT_INFO_PREFIX, username)
	if err != nil {
		return nil, err
	}
	//get data from dataStore
	data, exists := userlib.DatastoreGet(key)
	if !exists {
		userlib.DebugMsg("u:" + username + " p:" + password + "does not exist")
		return nil, errors.New("username not found error")
	}

	saltkey, err := makeDataStoreKeyAll(SALT_PREFIX, username)

	if err != nil {
		return nil, err
	}

	//get salt from dataStore
	salt, exists := userlib.DatastoreGet(saltkey)
	if !exists {
		userlib.DebugMsg("u:" + username + "salt does not exist")
		return nil, errors.New("salt not found error")
	}

	//consruct symmetric key to decrypt user data
	var symkey []byte = userlib.Argon2Key([]byte(password), salt, USER_STRUCT_KEY_BYTES)

	var decrypted []byte = userlib.SymDec(symkey, data[64:])

	//generate HMAC of decrypted message
	hmac, err := userlib.HMACEval(symkey, decrypted)
	if err != nil {
		return nil, err
	}

	//get HMAC from downloaed data (first 64 bytes)
	var hmacOld []byte = data[:64]

	//check to see if HMACS agree, if not, data was corrupted or tampered with
	if !userlib.HMACEqual(hmac, hmacOld) {
		return nil, errors.New("MAC doesn't match, user data has been tampered with")
	}

	//convert json to Go user struct
	json.Unmarshal(decrypted, &userdata)

	return &userdata, nil
}

//Not tested yet.
func constructFileBlocks(data []byte) (blockCount uint32, headptr *Block) {

	head := Block{
		BlockID:  0,
		Contents: data[:min(len(data), MAX_BLOCK_SIZE)],
		Next:     nil,
	}

	var prev Block = head

	for i := MAX_BLOCK_SIZE; i < len(data); i += MAX_BLOCK_SIZE {
		k := uint32(i)
		current := Block{
			BlockID:  k / MAX_BLOCK_SIZE,
			Contents: data[k:min(len(data), i+MAX_BLOCK_SIZE)],
			Next:     nil,
		}

		prev.Next = &current
		prev = current
	}

	blockCount = uint32(len(data) / MAX_BLOCK_SIZE)
	if len(data)%MAX_BLOCK_SIZE > 0 {
		blockCount++
	}

	return blockCount, &head

}

func (metadata Metadata) storeFileBlocks(headptr *Block, filePK userlib.PublicKeyType, fileDSSK userlib.DSSignKey) (err error) {

	for block := headptr; block != nil; block = block.Next {
		contents, err := json.Marshal(*block)
		if err != nil {
			return err
		}
		record, err := encryptAndSign(contents, filePK, fileDSSK)
		if err != nil {
			return err
		}
		key, err := makeDataStoreKeyAll(BLOCK_PREFIX, metadata.Owner, metadata.Filename, string(block.BlockID))
		if err != nil {
			return err
		}
		userlib.DatastoreSet(key, record)
	}
	return nil
}

// This stores a file in the datastore.
//
// The plaintext of the filename + the plaintext and length of the filename
// should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {

	filekey, err := makeDataStoreKeyAll(METADATA_PREFIX, userdata.Username, filename)
	if err != nil {
		return
	}
	_, exists := userlib.DatastoreGet(filekey)

	if !exists {

		sharetree := Sharetree{
			Parent:   userdata.Username,
			Children: []string{},
		}

		metadata := Metadata{
			Owner:      userdata.Username,
			Filename:   filename,
			BlockCount: 0,
			Head:       nil,
			Members:    []string{userdata.Username},
			Sharetree:  []Sharetree{sharetree},
		}

		blockCount, headptr := constructFileBlocks(data)

		metadata.BlockCount = blockCount
		metadata.Head = headptr

		filePublicKey, filePrivateKey, _ := userlib.PKEKeyGen()
		fileDSSignKey, fileDSVerifyKey, _ := userlib.DSKeyGen()

		userlib.KeystoreSet(FILEKEY_PREFIX+metadata.Owner+metadata.Filename, filePublicKey)
		userlib.KeystoreSet(FILE_DS_PREFIX+metadata.Owner+metadata.Filename, fileDSVerifyKey)
		metadata.storeFileBlocks(headptr, filePublicKey, fileDSSignKey)

		metadataJSON, _ := json.Marshal(metadata)
		record, _ := encryptAndSign(metadataJSON, filePublicKey, fileDSSignKey)
		key, _ := makeDataStoreKeyAll(METADATA_PREFIX, metadata.Owner, metadata.Filename)
		userlib.DatastoreSet(key, record)

		userSignKey, userVerifyKey, _ := userlib.DSKeyGen()
		userlib.KeystoreSet(USER_DS_PREFIX+userdata.Username+metadata.Filename, userVerifyKey)

		filePrivateKeyJSON, _ := json.Marshal(filePrivateKey)
		fileDSSignKeyJSON, _ := json.Marshal(fileDSSignKey)
		accessToken, _ := encryptAndSign(
			filePrivateKeyJSON,
			userdata.PublicKey,
			userSignKey,
		)

		signingToken, _ := encryptAndSign(
			fileDSSignKeyJSON,
			userdata.PublicKey,
			userSignKey,
		)

		fileInfoToken, _ := json.Marshal([]string{metadata.Owner, metadata.Filename})

		key, err = makeDataStoreKeyAll(ACCESS_TOKEN_PREFIX, userdata.Username, metadata.Filename)
		userlib.DatastoreSet(key, accessToken)

		key, err = makeDataStoreKeyAll(SIGNING_TOKEN_PREFIX, userdata.Username, metadata.Filename)
		userlib.DatastoreSet(key, signingToken)

		key, err = makeDataStoreKeyAll(FILE_INFO_TOKEN_PREFIX, userdata.Username, metadata.Filename)
		userlib.DatastoreSet(key, fileInfoToken)

		userdata.OwnedFiles = append(userdata.OwnedFiles, metadata.Filename)

		userJSON, _ := json.Marshal(userdata)
		userUUID, _ := makeDataStoreKeyAll(ACCOUNT_INFO_PREFIX, userdata.Username)
		userlib.DatastoreSet(userUUID, userJSON)

	} else {

	}
	/* //TODO: This is a toy implementation.
	UUID, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	packaged_data, _ := json.Marshal(data)
	userlib.DatastoreSet(UUID, packaged_data)
	//End of toy implementation */

	return
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	return errors.New("Not implemented.")
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {

	accessTokenKey, _ := makeDataStoreKeyAll(ACCESS_TOKEN_PREFIX, userdata.Username, filename)

	accessToken, ok := userlib.DatastoreGet(accessTokenKey)
	fmt.Printf("%s\n", accessToken)
	if !ok {
		userlib.DebugMsg("u:" + userdata.Username + " does not have access any file named f:" + filename)
		return nil, errors.New("username not found error")
	}

	fileInfoTokenKey, _ := makeDataStoreKeyAll(FILE_INFO_TOKEN_PREFIX, userdata.Username, filename)

	fileInfoToken, _ := userlib.DatastoreGet(fileInfoTokenKey)

	var filePrivateKey userlib.PKEDecKey
	var ownerAndFilename []string

	userVerifyKey, _ := userlib.KeystoreGet(USER_DS_PREFIX + userdata.Username + filename)

	err = decryptAndVerify(accessToken, filePrivateKey, userdata.PrivateKey, userVerifyKey)
	if err != nil {
		return nil, errors.New("Digital Signature doesn't match, u:" + userdata.Username + "'s access token has been tampered with")
	}

	err = decryptAndVerify(fileInfoToken, ownerAndFilename, userdata.PrivateKey, userVerifyKey)
	if err != nil {
		return nil, errors.New("Digital Signature doesn't match, u:" + userdata.Username + "'s info token has been tampered with")
	}

	fileVerifyKey, _ := userlib.KeystoreGet(FILE_DS_PREFIX + ownerAndFilename[0] + ownerAndFilename[1])

	var key userlib.UUID
	var metadata Metadata

	key, _ = makeDataStoreKeyAll(METADATA_PREFIX, ownerAndFilename[0], ownerAndFilename[1])
	metadataJSON, _ := userlib.DatastoreGet(key)
	err = decryptAndVerify(metadataJSON, metadata, filePrivateKey, fileVerifyKey)

	var blocks []byte
	var blockJSON []byte

	for i := 0; i < int(metadata.BlockCount); i++ {
		var block Block
		key, _ = makeDataStoreKeyAll(BLOCK_PREFIX, metadata.Owner, metadata.Filename, string(i))
		blockJSON, _ = userlib.DatastoreGet(key)
		err = decryptAndVerify(blockJSON, block, filePrivateKey, fileVerifyKey)
		blocks = append(blocks, block.Contents...)
	}

	/*//TODO: This is a toy implementation.
	UUID, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	packaged_data, ok := userlib.DatastoreGet(UUID)
	if !ok {
		return nil, errors.New(strings.ToTitle("File not found!"))
	}
	json.Unmarshal(packaged_data, &data)
	return data, nil
	//End of toy implementation*/

	return blocks, nil
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
