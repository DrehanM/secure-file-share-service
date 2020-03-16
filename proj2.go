package proj2

// CS 161 Project 2 Spring 2020
// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder. We will be very upset.

import (
	// You neet to add with
	// go get github.com/cs161-staff/userlib

	"strconv"

	"github.com/cs161-staff/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging, etc...

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

	MAX_BLOCK_SIZE = 256
	FILE_KEY_SIZE  = 16
	MAC_SIZE       = 64
	RSA_SIGN_BYTES = 256

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

func makeDataStoreKeyAll(parts ...string) (key uuid.UUID, err error) {
	var concat string

	for _, part := range parts {
		hash, _ := makeDataStoreKey(part)
		concat += strings.ReplaceAll(hash.String(), "-", "")
	}

	return makeDataStoreKey(concat)
}

func encryptAndMAC(v interface{}, symKey []byte) ([]byte, error) {
	message, _ := json.Marshal(v)
	IV := userlib.RandomBytes(BLOCK_STRUCT_IV_BYTES)
	ciphertext := userlib.SymEnc(symKey, IV, message)
	MAC, err := userlib.HMACEval(symKey, message)
	if err != nil {
		return nil, err
	}

	record := addSignatureToCipher(MAC, ciphertext)

	return record, nil
}

func decryptAndMACEval(contents []byte, symKey []byte) (message []byte, err error) {
	if len(contents) <= MAC_SIZE {
		return nil, errors.New("record corrupted")
	}
	MAC := contents[:MAC_SIZE]
	ciphertext := contents[MAC_SIZE:]
	message = userlib.SymDec(symKey, ciphertext)

	calculatedMAC, err := userlib.HMACEval(symKey, message)

	if err != nil {
		return nil, err
	}

	ok := userlib.HMACEqual(MAC, calculatedMAC)
	if !ok {
		return nil, errors.New("mac not equal")
	}
	return message, nil
}

func decryptAndMACEvalBlock(contents []byte, block *Block, symKey []byte) (err error) {

	message, err := decryptAndMACEval(contents, symKey)
	if err != nil {
		return err
	}

	json.Unmarshal(message, block)

	return nil
}

func decryptAndMACEvalMetaData(contents []byte, metaData *Metadata, symKey []byte) (err error) {

	message, err := decryptAndMACEval(contents, symKey)
	if err != nil {
		return err
	}

	json.Unmarshal(message, metaData)
	return nil
}

func encryptAndSign(v interface{}, publicKey userlib.PKEEncKey, signingKey userlib.DSSignKey) ([]byte, error) {
	message, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	ciphertext, err := userlib.PKEEnc(publicKey, message)

	if err != nil {
		return nil, err
	}
	record, err := signMessage(ciphertext, message, signingKey)

	if err != nil {
		return nil, err
	}

	return record, nil
}

func decryptAndVerifyAccessToken(contents []byte, accessToken *AccessToken, privateKey userlib.PKEDecKey, verifyKey userlib.DSVerifyKey) (err error) {
	signature := contents[:RSA_SIGN_BYTES]
	ciphertext := contents[RSA_SIGN_BYTES:]
	message, _ := userlib.PKEDec(privateKey, ciphertext)

	err = userlib.DSVerify(verifyKey, message, signature)
	if err != nil {
		//Token may have changed and is now signed by owner
		err = json.Unmarshal(message, accessToken)
		ownerVerifyKey, ok := userlib.KeystoreGet(USER_DS_PREFIX + accessToken.OwnerUsername)
		if !ok {
			return errors.New("could not get owner verify key from keystore")
		}
		err = userlib.DSVerify(ownerVerifyKey, message, signature)
		if err != nil {
			return errors.New("access token has been tampered with")
		}
		return nil
	}
	err = json.Unmarshal(message, accessToken)
	return nil
}

func decryptAndVerifyAccessTokenRecipient(contents []byte, accessToken *AccessToken, privateKey userlib.PKEDecKey, sender string) (err error) {
	signature := contents[:RSA_SIGN_BYTES]
	ciphertext := contents[RSA_SIGN_BYTES:]
	message, _ := userlib.PKEDec(privateKey, ciphertext)

	verifyKey, ok := userlib.KeystoreGet(USER_DS_PREFIX + sender)
	if !ok {
		return errors.New("owner's public verify key not found in keystore")
	}

	err = userlib.DSVerify(verifyKey, message, signature)
	if err != nil {
		return err
	}

	err = json.Unmarshal(message, accessToken)

	return nil
}

func min(a int, b int) (retval int) {
	if a < b {
		return a
	}
	return b
}

func loadAccessToken(accessToken *AccessToken, username string, filename string, privateKey userlib.PKEDecKey) (exists bool, err error) {
	accessTokenKey, _ := makeDataStoreKeyAll(ACCESS_TOKEN_PREFIX, username, filename)
	accessTokenRecord, ok := userlib.DatastoreGet(accessTokenKey)
	if !ok {
		return false, errors.New("access token not found error")
	}

	if len(accessTokenRecord) <= RSA_SIGN_BYTES {
		return false, errors.New("access token corrupted")
	}

	userVerifyKey, _ := userlib.KeystoreGet(USER_DS_PREFIX + username)

	err = decryptAndVerifyAccessToken(accessTokenRecord, accessToken, privateKey, userVerifyKey)
	if err != nil {
		return true, err
	}

	return true, nil

}

func loadMetaData(metaData *Metadata, accessToken *AccessToken) (err error) {

	key, _ := makeDataStoreKeyAll(METADATA_PREFIX, accessToken.OwnerUsername, accessToken.Filename)
	record, ok := userlib.DatastoreGet(key)
	if !ok {
		return errors.New("metadata not found error")
	}

	err = decryptAndMACEvalMetaData(record, metaData, accessToken.FileKey)
	if err != nil {
		return err
	}
	return nil
}

func loadBlock(block *Block, blockID int, metaData *Metadata, accessToken *AccessToken) (err error) {
	key, _ := makeDataStoreKeyAll(BLOCK_PREFIX, metaData.Owner, metaData.Filename, strconv.Itoa(blockID))
	record, ok := userlib.DatastoreGet(key)
	if !ok {
		return errors.New("file block not found error")
	}

	err = decryptAndMACEvalBlock(record, block, accessToken.FileKey)
	if err != nil {
		return err
	}
	return nil
}

// The structure definition for a user record
type User struct {
	Username   string
	PrivateKey userlib.PrivateKeyType
	PublicKey  userlib.PublicKeyType
	SignKey    userlib.DSSignKey
	OwnedFiles []string

	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

type Sharebranch struct {
	Filename string
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
	Sharetree  []Sharebranch
}

type AccessToken struct {
	FileKey       []byte
	OwnerUsername string
	Filename      string
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

	_, exists := userlib.KeystoreGet(username)

	if exists {
		return nil, errors.New("cannot create new user. username is taken")
	}

	userdata.OwnedFiles = []string{}
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

	//construct key user struct in dataStore
	key, err := makeDataStoreKeyAll(ACCOUNT_INFO_PREFIX, userdata.Username)
	if err != nil {
		return nil, err
	}

	//construct key for salt in dataStore
	saltkey, err := makeDataStoreKeyAll(SALT_PREFIX, userdata.Username)
	if err != nil {
		return nil, err
	}

	var userVerifyKey userlib.DSVerifyKey

	userdata.SignKey, userVerifyKey, _ = userlib.DSKeyGen()
	userlib.KeystoreSet(USER_DS_PREFIX+userdata.Username, userVerifyKey)

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
		return nil, errors.New("username not found error")
	}

	if len(data) <= 64 {
		return nil, errors.New("userdata corrupted")
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
func constructFileBlocks(startID uint32, data []byte) (blockCount uint32, headptr *Block) {

	head := Block{
		BlockID:  startID,
		Contents: data[:min(len(data), MAX_BLOCK_SIZE)],
		Next:     nil,
	}

	var prev *Block = &head

	for i := MAX_BLOCK_SIZE; i < len(data); i += MAX_BLOCK_SIZE {
		k := uint32(i)
		current := Block{
			BlockID:  startID + k/MAX_BLOCK_SIZE,
			Contents: data[k:min(len(data), i+MAX_BLOCK_SIZE)],
			Next:     nil,
		}

		prev.Next = &current
		prev = &current
	}

	blockCount = uint32(len(data) / MAX_BLOCK_SIZE)
	if len(data)%MAX_BLOCK_SIZE > 0 {
		blockCount++
	}

	return blockCount, &head

}

func (metadata Metadata) storeFileBlocks(headptr *Block, fileKey []byte) (err error) {

	for block := headptr; block != nil; block = block.Next {
		record, err := encryptAndMAC(*block, fileKey)
		if err != nil {
			return err
		}
		key, err := makeDataStoreKeyAll(BLOCK_PREFIX, metadata.Owner, metadata.Filename, strconv.Itoa(int(block.BlockID)))
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

	//construct key for metadata in dataStore
	var accessToken AccessToken

	exists, _ := loadAccessToken(&accessToken, userdata.Username, filename, userdata.PrivateKey)

	if !exists {
		sharebranch := Sharebranch{
			Filename: filename,
			Parent:   userdata.Username,
			Children: []string{},
		}

		metadata := Metadata{
			Owner:      userdata.Username,
			Filename:   filename,
			BlockCount: 0,
			Sharetree:  []Sharebranch{sharebranch},
		}

		blockCount, headptr := constructFileBlocks(0, data)

		metadata.BlockCount = blockCount

		fileKey := userlib.RandomBytes(FILE_KEY_SIZE)

		metadata.storeFileBlocks(headptr, fileKey)

		metaDataKey, _ := makeDataStoreKeyAll(METADATA_PREFIX, userdata.Username, filename)
		metaDataRecord, _ := encryptAndMAC(metadata, fileKey)
		userlib.DatastoreSet(metaDataKey, metaDataRecord)

		accessToken := AccessToken{
			FileKey:       fileKey,
			OwnerUsername: metadata.Owner,
			Filename:      metadata.Filename,
		}

		accessTokenRecord, _ := encryptAndSign(
			accessToken,
			userdata.PublicKey,
			userdata.SignKey,
		)

		accessTokenKey, _ := makeDataStoreKeyAll(ACCESS_TOKEN_PREFIX, userdata.Username, metadata.Filename)
		userlib.DatastoreSet(accessTokenKey, accessTokenRecord)

	} else {
		var metadata Metadata

		loadMetaData(&metadata, &accessToken)

		blockCount, headptr := constructFileBlocks(0, data)

		metadata.BlockCount = blockCount

		metadata.storeFileBlocks(headptr, accessToken.FileKey)

		metaDataKey, _ := makeDataStoreKeyAll(METADATA_PREFIX, accessToken.OwnerUsername, accessToken.Filename)
		metaDataRecord, _ := encryptAndMAC(metadata, accessToken.FileKey)
		userlib.DatastoreSet(metaDataKey, metaDataRecord)

	}

	return
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
func (userdata *User) AppendFile(filename string, data []byte) (err error) {

	var accessToken AccessToken

	exists, err := loadAccessToken(&accessToken, userdata.Username, filename, userdata.PrivateKey)

	if err != nil {
		return err
	}

	if !exists {
		return errors.New("no such file:" + filename + " for user:" + userdata.Username)
	}

	var metadata Metadata

	err = loadMetaData(&metadata, &accessToken)
	if err != nil {
		return err
	}

	blockCount, head := constructFileBlocks(metadata.BlockCount, data)

	metadata.BlockCount += blockCount

	metadata.storeFileBlocks(head, accessToken.FileKey)

	metaDataRecord, _ := encryptAndMAC(metadata, accessToken.FileKey)
	metaDataKey, err := makeDataStoreKeyAll(METADATA_PREFIX, accessToken.OwnerUsername, accessToken.Filename)
	if err != nil {
		return
	}
	userlib.DatastoreSet(metaDataKey, metaDataRecord)

	return nil

}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.

func (userdata *User) LoadFile(filename string) (data []byte, err error) {

	var accessToken AccessToken

	exists, err := loadAccessToken(&accessToken, userdata.Username, filename, userdata.PrivateKey)
	if err != nil {
		return nil, err
	}

	if !exists {
		return nil, errors.New("no such file:" + filename + " for user:" + userdata.Username)
	}

	var metadata Metadata

	err = loadMetaData(&metadata, &accessToken)
	if err != nil {
		return nil, err
	}

	var file []byte

	for i := 0; i < int(metadata.BlockCount); i++ {
		var block Block
		err = loadBlock(&block, i, &metadata, &accessToken)
		if err != nil {
			return nil, err
		}
		if block.BlockID != uint32(i) {
			return nil, errors.New("tampering detected: file has been reordered")
		}
		file = append(file, block.Contents...)
	}

	return file, nil
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
func (userdata *User) ShareFile(filename string, recipient string) (magicString string, err error) {
	var ownerAccessToken AccessToken

	exists, err := loadAccessToken(&ownerAccessToken, userdata.Username, filename, userdata.PrivateKey)
	if err != nil {
		return "", err
	}

	if !exists {
		return "", errors.New("no such file:" + filename + " for user:" + userdata.Username)
	}

	var recipientAccessToken AccessToken = ownerAccessToken

	recipientPublicKey, ok := userlib.KeystoreGet(recipient)
	if !ok {
		return "", errors.New("recipient public key not in keystore")
	}

	record, err := encryptAndSign(recipientAccessToken, recipientPublicKey, userdata.SignKey)
	if err != nil {
		return "", err
	}

	//update sharetree

	var metaData Metadata

	loadMetaData(&metaData, &ownerAccessToken)

	for _, branch := range metaData.Sharetree {
		if strings.Compare(branch.Parent, userdata.Username) == 0 {
			branch.Children = append(branch.Children, recipient)
		}
	}

	metaDataKey, _ := makeDataStoreKeyAll(METADATA_PREFIX, userdata.Username, filename)
	metaDataRecord, _ := encryptAndMAC(metaData, ownerAccessToken.FileKey)
	userlib.DatastoreSet(metaDataKey, metaDataRecord)

	return string(record), nil
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string, magicString string) error {
	var accessToken AccessToken

	if len([]byte(magicString)) <= RSA_SIGN_BYTES {
		return errors.New("magic string is invalid")
	}

	accessTokenKey, _ := makeDataStoreKeyAll(ACCESS_TOKEN_PREFIX, userdata.Username, filename)
	_, exists := userlib.DatastoreGet(accessTokenKey)
	if exists {
		return errors.New("filename: " + filename + " already exists for user")
	}

	decryptAndVerifyAccessTokenRecipient([]byte(magicString), &accessToken, userdata.PrivateKey, sender)

	record, err := encryptAndSign(accessToken, userdata.PublicKey, userdata.SignKey)
	if err != nil {
		return err
	}

	accessTokenKey, _ = makeDataStoreKeyAll(ACCESS_TOKEN_PREFIX, userdata.Username, filename)

	var metadata Metadata

	err = loadMetaData(&metadata, &accessToken)
	if err != nil {
		return err
	}

	for i := 0; i < len(metadata.Sharetree); i++ {
		if metadata.Sharetree[i].Parent == sender {
			metadata.Sharetree[i].Children = append(metadata.Sharetree[i].Children, userdata.Username)
		}
	}

	newBranch := Sharebranch{
		Filename: filename,
		Children: []string{},
		Parent:   userdata.Username,
	}

	metadata.Sharetree = append(metadata.Sharetree, newBranch)

	metaDataKey, _ := makeDataStoreKeyAll(METADATA_PREFIX, accessToken.OwnerUsername, accessToken.Filename)
	metaDataRecord, _ := encryptAndMAC(metadata, accessToken.FileKey)
	userlib.DatastoreSet(metaDataKey, metaDataRecord)

	userlib.DatastoreSet(accessTokenKey, record)

	return nil

}

func deleteUserAccessToken(username string, filename string) {
	accessTokenKey, _ := makeDataStoreKeyAll(ACCESS_TOKEN_PREFIX, username, filename)
	userlib.DatastoreDelete(accessTokenKey)
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, targetUsername string) (err error) {
	var accessToken AccessToken

	exists, err := loadAccessToken(&accessToken, userdata.Username, filename, userdata.PrivateKey)

	if err != nil {
		return err
	}

	if !exists {
		return errors.New("no such file:" + filename + " for user:" + userdata.Username)
	}

	var metadata Metadata

	err = loadMetaData(&metadata, &accessToken)

	if err != nil {
		return err
	}

	if metadata.Owner != userdata.Username {
		return errors.New("cannot revoke file because user is not owner of file")
	}

	for _, branch := range metadata.Sharetree {
		if strings.Compare(branch.Parent, targetUsername) == 0 {
			deleteUserAccessToken(targetUsername, branch.Filename)
		}
	}

	newSharetree := revokeAllChildren(metadata.Sharetree, targetUsername)
	metadata.Sharetree = newSharetree

	data, _ := userdata.LoadFile(filename)

	err = reissueNewTokens(*userdata, metadata)

	if err != nil {
		return err
	}

	userdata.StoreFile(filename, data)

	return nil

}

func revokeAllChildren(sharetree []Sharebranch, targetParent string) []Sharebranch {
	var lostChildren, queue []string
	var target string
	for queue = []string{targetParent}; len(queue) > 0; {
		if len(queue) > 1 {
			target, queue = queue[0], queue[1:]
		} else {
			target, queue = queue[0], []string{}
		}
		sharetree, lostChildren = removeBranch(sharetree, target)
		queue = append(queue, lostChildren...)
	}
	return sharetree

}

func removeBranch(sharetree []Sharebranch, targetParent string) (trimmedSharetree []Sharebranch, lostChildren []string) {
	var curBranch Sharebranch
	for i := 0; i < len(sharetree); i++ {
		curBranch = sharetree[i]
		if curBranch.Parent == targetParent {
			deleteUserAccessToken(targetParent, curBranch.Filename)
			if i < len(sharetree)-1 {
				return append(sharetree[:i], sharetree[i+1:]...), curBranch.Children
			} else {
				return sharetree[:i], curBranch.Children
			}
		}
	}
	return sharetree, nil
}

func getParentNames(sharetree []Sharebranch) (names []string) {
	for _, branch := range sharetree {
		names = append(names, branch.Parent)
	}
	return names
}

func reissueNewTokens(ownerdata User, metadata Metadata) error {

	newFileKey := userlib.RandomBytes(FILE_KEY_SIZE)
	newAccessToken := AccessToken{
		FileKey:       newFileKey,
		OwnerUsername: metadata.Owner,
		Filename:      metadata.Filename,
	}

	ownerSignKey := ownerdata.SignKey

	for _, branch := range metadata.Sharetree {
		shareePublicKey, exists := userlib.KeystoreGet(branch.Parent)
		if !exists {
			return errors.New("could not find u:" + branch.Parent + "'s public key in keystore")
		}
		accessTokenRecord, err := encryptAndSign(newAccessToken, shareePublicKey, ownerSignKey)
		if err != nil {
			return err
		}
		accessTokenKey, err := makeDataStoreKeyAll(ACCESS_TOKEN_PREFIX, branch.Parent, branch.Filename)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(accessTokenKey, accessTokenRecord)
	}
	return nil
}
