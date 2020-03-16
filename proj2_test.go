package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	_ "encoding/hex"
	_ "encoding/json"
	_ "errors"
	"reflect"
	_ "strconv"
	_ "strings"
	"testing"

	"github.com/cs161-staff/userlib"
	"github.com/google/uuid"
	_ "github.com/google/uuid"
)

func clear() {
	// Wipes the storage so one test does not affect another
	userlib.DatastoreClear()
	userlib.KeystoreClear()
}

func TestInit(t *testing.T) {
	clear()
	t.Log("Initialization test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u.Username)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
}

func TestInitDuplicateUser(t *testing.T) {
	clear()
	t.Log("Test: Initialization attempt for a taken username.")

	userlib.SetDebugStatus(true)

	_, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}

	_, err = InitUser("alice", "barfu")

	if err == nil {
		t.Error("Failed to error on duplicate username")
	} else {
		t.Logf("Task failed successfully %s", err)
	}
	return
}

func TestGetUser(t *testing.T) {
	clear()
	t.Log("GetUser Test: general functionality")
	userlib.SetDebugStatus(true)

	_, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	u1, err := InitUser("alice1", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	t.Log("Got user", u1.Username)

	nu1, err := GetUser("alice", "fubar")
	t.Log("Got user again", nu1.Username)

	nu2, err := GetUser("alice1", "fubar")
	t.Log("Got user again", nu2.Username)

	if err != nil || nu1.Username != "alice" || nu2.Username != "alice1" {
		t.Error("Failed to Get User")
		return
	}
}

func TestGetUserNotExist(t *testing.T) {
	clear()
	t.Log("Test: return error if user does not exit")
	userlib.SetDebugStatus(true)

	_, err := GetUser("alice", "fubar")
	if err == nil {
		t.Error("Failed to error when user does not exist.")
	} else {
		t.Logf("Task failed successfully %s", err)
	}
}

func TestGetUserWrongPassword(t *testing.T) {
	clear()
	t.Log("GetUser Test: return error for wrong password")
	userlib.SetDebugStatus(true)

	_, err := InitUser("alice", "password")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err = GetUser("alice", "this is the wrong password")
	if err == nil {
		t.Error("Failed to error when user inputs wrong password.")
	} else {
		t.Logf("Task failed successfully %s", err)
	}
}

func TestGetUserCorruptedUser(t *testing.T) {
	clear()
	t.Log("GetUser Test: return error for corrupted userdata record")
	userlib.SetDebugStatus(true)

	_, err := InitUser("alice", "password")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	scrambleDatastore()

	u, err := GetUser("alice", "password")
	if err == nil {
		t.Error("Failed to error when userdata record is tampered", u)
	} else {
		t.Logf("Task failed successfully %s", err)
	}

}

func TestGetUserMultipleInstances(t *testing.T) {
	clear()
	t.Log("GetUser Test: Multiple instances of the same user")
	userlib.SetDebugStatus(true)

	_, err := InitUser("alice", "password")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	alice1, err := GetUser("alice", "password")
	t.Log("Got user", alice1.Username)

	alice2, err := GetUser("alice", "password")
	t.Log("Got user", alice2.Username)

	if &alice1 == &alice2 || alice1.Username != alice2.Username {
		t.Error("Failed to initialize multiple independent pointers to same user record")
	}
}

func TestStorage(t *testing.T) {
	clear()
	t.Log("Storage Test: general functionality")
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
}

func TestStorageSimpleOverwrite(t *testing.T) {
	clear()
	t.Log("Storage Test: simple overwrite")

	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v1 := []byte("This is a test")
	u.StoreFile("file1", v1)

	v2 := []byte("This is an overwrite")
	u.StoreFile("file1", v2)

	check, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v2, check) {
		t.Error("Downloaded file is not the same", v2, check)
		return
	}
}

func TestStorageOverwriteWithSharedUsers(t *testing.T) {
	clear()
	t.Log("Integration Test: verify that overwrite is visible to all shared users")

	alice, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	bob, err := InitUser("bob", "bufar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v1 := []byte("This is a test")
	alice.StoreFile("file1", v1)

	magic, err := alice.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share file", err)
	}

	err = bob.ReceiveFile("myfile", "alice", magic)
	if err != nil {
		t.Error("Failed to receive file", err)
	}

	v2 := []byte("This is an overwrite")
	alice.StoreFile("file1", v2)

	check1, err := alice.LoadFile("file1")
	if err != nil {
		t.Error("Failed to load file", err)
	}
	check2, err := bob.LoadFile("myfile")
	if err != nil {
		t.Error("Failed to load file", err)
	}

	if !reflect.DeepEqual(check1, v2) {
		t.Error("Failed to overwrite file for owner")
	}

	if !reflect.DeepEqual(check2, v2) {
		t.Error("Failed to overwrite file for shared user")
	}
}

func TestLoadInvalidFile(t *testing.T) {
	clear()
	t.Log("Load Test: return error on loading nonexistent file")
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err2 := u.LoadFile("this file does not exist")
	if err2 == nil {
		t.Error("Downloaded a nonexistent file", err2)
		return
	}
}

func TestLoadCorruptedFile(t *testing.T) {
	clear()
	t.Log("Load Test: return error if a block record is corrupted")
	alice, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v1 := []byte("This is a test")
	alice.StoreFile("file1", v1)

	scrambleDatastore()

	check1, err := alice.LoadFile("file1")

	if err == nil {
		t.Error("Failed to error when file block is corrupted", check1)
	} else {
		t.Logf("Task failed successfully %s", err)
	}
}

func TestAppend(t *testing.T) {
	clear()
	t.Log("Append Test: general functionality")
	alice, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v1 := []byte("This is the first entry")
	alice.StoreFile("file1", v1)

	entry2 := []byte("This is the second entry")
	err = alice.AppendFile("file1", entry2)

	if err != nil {
		t.Error("Failed to append to file", err)
	}

	composite := append(v1, entry2...)

	file1, err := alice.LoadFile("file1")
	if err != nil {
		t.Error("Failed to load file", err)
	}

	if !reflect.DeepEqual(composite, file1) {
		t.Error("File equality failed, did not append correctly", file1)
	}
}

func TestAppendInvalidFile(t *testing.T) {
	clear()
	t.Log("Append Test: return error on appending to nonexistent file")
	alice, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v1 := []byte("This is the first entry")
	alice.StoreFile("file1", v1)

	entry2 := []byte("This is the second entry")
	err = alice.AppendFile("wrong file", entry2)

	if err == nil {
		t.Error("Failed to error when appending to nonexistent file", err)
	} else {
		t.Logf("Task failed successfully %s", err)
	}
}

func TestAppendWithSharedUsers(t *testing.T) {
	clear()
	t.Log("Integration Test: verify that append is visible to all shared users")

	alice, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	bob, err := InitUser("bob", "bufar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v1 := []byte("This is a test")
	alice.StoreFile("file1", v1)

	magic, err := alice.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share file", err)
	}

	err = bob.ReceiveFile("myfile", "alice", magic)
	if err != nil {
		t.Error("Failed to receive file", err)
	}

	v2 := []byte("This is an append")
	alice.AppendFile("file1", v2)

	check1, err := alice.LoadFile("file1")
	if err != nil {
		t.Error("Failed to load file", err)
	}
	check2, err := bob.LoadFile("myfile")
	if err != nil {
		t.Error("Failed to load file", err)
	}

	if !reflect.DeepEqual(check1, append(v1, v2...)) {
		t.Error("Failed to append to file for owner")
	}

	if !reflect.DeepEqual(check2, append(v1, v2...)) {
		t.Error("Failed to append to file for shared user")
	}
}

func TestAppendWithSharedUsers2(t *testing.T) {
	clear()
	t.Log("Integration Test: verify that append is visible to all shared users")
	u, _ := InitUser("alice", "fubar")

	u2, _ := InitUser("bob", "foobar")

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var magic_string string

	v, _ = u.LoadFile("file1")

	magic_string, _ = u.ShareFile("file1", "bob")

	_ = u2.ReceiveFile("file2", "alice", magic_string)

	newData := make([]byte, 2048*10)
	newData[2048*5+12] = 9

	u2.AppendFile("file2", newData)

	fu, _ := u.LoadFile("file1")
	fu2, _ := u2.LoadFile("file2")

	if !reflect.DeepEqual(fu, fu2) {
		t.Error("files not equal")
		return
	}

	if !reflect.DeepEqual(append(v, newData...), fu) {
		t.Error("append didn't save")
	}

}

func TestShare(t *testing.T) {
	clear()
	t.Log("Share Test: general functionality")
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var v2 []byte
	var magic_string string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

}

func TestShareCorruptedToken(t *testing.T) {
	clear()
	t.Log("Share Test: return error if shared token is corrupted")
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var magic_string string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string+"oops")
	if err == nil {
		t.Error("Failed to error with corrupted token")
	} else {
		t.Logf("Task failed successfully %s", err)
	}
}

func TestShareIdenticalNames(t *testing.T) {
	clear()
	t.Log("Share Test: ensure that recipient only has access to sender's shared file and not files with same names")
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is my first file")
	u.StoreFile("file1", v)

	w := []byte("This is my second file")
	u.StoreFile("file2", w)

	var magic_string string

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err := u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}

	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

}

func TestShareRestrictedAccess(t *testing.T) {
	clear()
	t.Log("Share Test: ensure that recipient only has access to sender's shared file and not all of sender's files")
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is my first file")
	u.StoreFile("fileA", v)

	w := []byte("This is my second file")
	u.StoreFile("fileB", w)

	var magic_string string

	magic_string, err = u.ShareFile("fileA", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err := u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}

	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

	_, err = u2.LoadFile("fileB")
	if err == nil {
		t.Error("Failed to error on trying to access nonexistent file", err)
	}

}

//Function prologue for tests with big sharing tree
// NOT A TEST
/* Sharing hierarchy:
	 Alice
	/	 \
   /	  \
 Bob	 Charlie
		/		\
	   /		 \
	 David		Eric
*/
func helperBigSharePrologue(t *testing.T) ([]byte, *User, *User, *User, *User, *User, error) {
	alice, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize alice", err)
		return nil, nil, nil, nil, nil, nil, err
	}
	bob, err := InitUser("bob", "foobar")
	if err != nil {
		t.Error("Failed to initialize bob", err)
		return nil, nil, nil, nil, nil, nil, err
	}

	charlie, err := InitUser("charlie", "barfu")
	if err != nil {
		t.Error("Failed to initialize charlie", err)
		return nil, nil, nil, nil, nil, nil, err
	}

	david, err := InitUser("david", "blatt slatt")
	if err != nil {
		t.Error("Failed to initialize david", err)
		return nil, nil, nil, nil, nil, nil, err
	}

	eric, err := InitUser("eric", "slime love all the time")
	if err != nil {
		t.Error("Failed to initialize david", err)
		return nil, nil, nil, nil, nil, nil, err
	}

	file := []byte("This is my first file")
	alice.StoreFile("fileA", file)

	/* ----- START SHARING  ----- */
	magic_string, err := alice.ShareFile("fileA", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return nil, nil, nil, nil, nil, nil, err
	}
	err = bob.ReceiveFile("fileB", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return nil, nil, nil, nil, nil, nil, err
	}

	magic_string, err = alice.ShareFile("fileA", "charlie")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return nil, nil, nil, nil, nil, nil, err
	}
	err = charlie.ReceiveFile("fileC", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return nil, nil, nil, nil, nil, nil, err
	}

	magic_string, err = charlie.ShareFile("fileC", "david")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return nil, nil, nil, nil, nil, nil, err
	}
	err = david.ReceiveFile("fileD", "charlie", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return nil, nil, nil, nil, nil, nil, err
	}

	magic_string, err = charlie.ShareFile("fileC", "eric")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return nil, nil, nil, nil, nil, nil, err
	}
	err = eric.ReceiveFile("fileE", "charlie", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return nil, nil, nil, nil, nil, nil, err
	}
	return file, alice, bob, charlie, david, eric, nil
}

func TestShareHierarchy(t *testing.T) {
	clear()
	t.Log("Share Test: check to see if all sharees can see file changes")

	_, alice, bob, charlie, david, eric, err := helperBigSharePrologue(t)
	if err != nil {
		return
	}
	/* ----- END SHARING  ----- */

	/* ----- START ALICE EDIT AND VERIFY ----- */

	fileA := []byte("This is my second file")
	alice.StoreFile("fileA", fileA)

	fileB, err := bob.LoadFile("fileB")
	fileC, err := charlie.LoadFile("fileC")
	fileD, err := david.LoadFile("fileD")
	fileE, err := eric.LoadFile("fileE")

	if !reflect.DeepEqual(fileB, fileA) || !reflect.DeepEqual(fileC, fileA) || !reflect.DeepEqual(fileD, fileA) || !reflect.DeepEqual(fileE, fileA) {
		t.Error("Shared file was not updated for all users after owner edit")
		return
	}

	/* ----- END ALICE EDIT AND VERIFY ----- */

	/* ----- START BOB APPEND AND VERIFY ----- */

	appendBob := []byte("I am bob and I am adding to the file after owner edit")
	bob.AppendFile("fileB", appendBob)

	currentFile := append(fileA, appendBob...)

	fileA, err = alice.LoadFile("fileA")
	fileB, err = bob.LoadFile("fileB")
	fileC, err = charlie.LoadFile("fileC")
	fileD, err = david.LoadFile("fileD")
	fileE, err = eric.LoadFile("fileE")

	if !reflect.DeepEqual(fileA, currentFile) || !reflect.DeepEqual(fileB, currentFile) || !reflect.DeepEqual(fileC, currentFile) || !reflect.DeepEqual(fileD, currentFile) || !reflect.DeepEqual(fileE, currentFile) {
		t.Error("Shared file was not updated for all users after sharee edit")
		t.Logf("actual: %s\nAlice: %s\nBob: %s\nCharlie: %s\nDavid: %s\nEric: %s\n", string(currentFile), string(fileA), string(fileB), string(fileC), string(fileD), string(fileE))
		return
	}

	/* ----- END BOB APPEND AND VERIFY ----- */

}

func TestReceiveDuplicateFilename(t *testing.T) {
	clear()
	t.Log("Receive Test: return error when filename already exists for sharee")

	alice, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize alice", err)
		return
	}
	bob, err := InitUser("bob", "foobar")
	if err != nil {
		t.Error("Failed to initialize bob", err)
		return
	}

	fileA := []byte("This is my first file")
	alice.StoreFile("file1", fileA)

	fileB := []byte("This is my first file and I am Bob")
	bob.StoreFile("file1", fileB)

	magicString, err := alice.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share file", err)
		return
	}

	err = bob.ReceiveFile("file1", "alice", magicString)
	if err == nil {
		t.Error("Failed to raise error for duplicate filename for bob")
	}
}

func TestReceiveTwice(t *testing.T) {
	clear()
	t.Log("Receive Test: return error when user attempts to receive file twice")

	alice, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize alice", err)
		return
	}
	bob1, err := InitUser("bob", "foobar")
	if err != nil {
		t.Error("Failed to initialize bob", err)
		return
	}

	bob2, err := GetUser("bob", "foobar")
	if err != nil {
		t.Error("Failed to create second instance of bob", err)
		return
	}

	fileA := []byte("This is my first file")
	alice.StoreFile("file1", fileA)

	magicString, err := alice.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share file", err)
		return
	}

	err = bob1.ReceiveFile("file1", "alice", magicString)
	if err != nil {
		t.Error("Failed to receive file", err)
	}

	err = bob2.ReceiveFile("file2", "alice", magicString)
	if err == nil {
		t.Error("Failed to raise error when receiving the same token twice")
	}
}

func TestRevoke(t *testing.T) {
	clear()
	u, _ := InitUser("alice", "fubar")

	u2, _ := InitUser("bob", "foobar")

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var magic_string string

	v, _ = u.LoadFile("file1")

	magic_string, _ = u.ShareFile("file1", "bob")

	_ = u2.ReceiveFile("file2", "alice", magic_string)

	newData := make([]byte, 2048*10)
	newData[2048*5+12] = 9

	u2.AppendFile("file2", newData)

	u.RevokeFile("file1", "bob")

	f, err := u2.LoadFile("file2")
	if err == nil || f != nil {
		t.Error("was able to load file")
	}

	err = u2.AppendFile("file2", newData)
	if err == nil {
		t.Error("sharee appended after revoke")
	}

	f, err = u.LoadFile("file1")

	if reflect.DeepEqual(append(v, append(newData, newData...)...), f) {
		t.Error("sharee appended after revoke")
	}

}

func TestRevokeShareAgain(t *testing.T) {
	clear()
	u, _ := InitUser("alice", "fubar")

	u2, _ := InitUser("bob", "foobar")

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var magic_string string

	v, _ = u.LoadFile("file1")

	magic_string, _ = u.ShareFile("file1", "bob")

	_ = u2.ReceiveFile("file2", "alice", magic_string)

	u.RevokeFile("file1", "bob")

	err := u2.AppendFile("file2", []byte(" appended data attempt"))

	if err == nil {
		t.Error("Failed to error on illegal append")
	}

	block2 := []byte(" appended data by alice")
	err = u.AppendFile("file1", block2)

	magic_string, _ = u.ShareFile("file1", "bob")

	_ = u2.ReceiveFile("file2", "alice", magic_string)

	file, err := u2.LoadFile("file2")

	if !reflect.DeepEqual(file, append(v, block2...)) {
		t.Error("Did not correctly reshare")
	}

}

func TestRevokeTree(t *testing.T) {
	clear()
	u, _ := InitUser("alice", "fubar")

	u2, _ := InitUser("bob", "foobar")

	u3, _ := InitUser("cherie", "fubar")

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var magic_string string

	v, _ = u.LoadFile("file1")

	magic_string, _ = u.ShareFile("file1", "bob")

	_ = u2.ReceiveFile("file2", "alice", magic_string)

	magic_string, _ = u2.ShareFile("file2", "cherie")

	_ = u3.ReceiveFile("file3", "bob", magic_string)

	_, err := u3.LoadFile("file3")
	if err != nil {
		t.Error("third branch couldn't load file")
		return
	}

	newData := make([]byte, 2048*5)
	newData[2048*2+4] = 9

	err = u3.AppendFile("file3", newData)
	if err != nil {
		t.Error("third branch couldn't append file")
	}

	f3, _ := u3.LoadFile("file3")
	f1, _ := u.LoadFile("file1")
	f2, _ := u2.LoadFile("file2")

	if !reflect.DeepEqual(f1, f2) || !reflect.DeepEqual(f2, f3) {
		t.Error("appends didn't affect all users")
	}

	if !reflect.DeepEqual(f1, append(v, newData...)) {
		t.Error("appends didnt update")
	}

	u.RevokeFile("file1", "bob")

	f, err := u3.LoadFile("file3")
	if err == nil || f != nil {
		t.Error("was able to load file")
	}

	err = u3.AppendFile("file3", newData)
	if err == nil {
		t.Error("sharee appended after revoke")
	}

	f, err = u.LoadFile("file1")

	if !reflect.DeepEqual(append(v, newData...), f) {
		t.Error("sharee appended after revoke")
	}

}

func TestRevokeChangeOfTokens(t *testing.T) {
	clear()
	t.Log("Share Test: check to if access token change after revoke is handled correctly")

	file, alice, _, charlie, david, eric, err := helperBigSharePrologue(t)
	if err != nil {
		return
	}
	// ----- END SHARING  -----

	// ----- START REVOKE -----
	err = alice.RevokeFile("fileA", "bob")
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}
	// ----- END REVOKE

	fileA, err := alice.LoadFile("fileA")
	if err != nil {
		t.Error("Failed to load file", err)
		return
	}
	fileC, err := charlie.LoadFile("fileC")
	if err != nil {
		t.Error("Failed to load file", err)
		return
	}
	fileD, err := david.LoadFile("fileD")
	if err != nil {
		t.Error("Failed to load file", err)
		return
	}
	fileE, err := eric.LoadFile("fileE")
	if err != nil {
		t.Error("Failed to load file", err)
		return
	}

	if !reflect.DeepEqual(file, fileA) || !reflect.DeepEqual(file, fileC) || !reflect.DeepEqual(file, fileD) || !reflect.DeepEqual(file, fileE) {
		t.Error("Failed to change tokens successfully")
	}
}

func TestRevokeCorruptedChangeOfTokens(t *testing.T) {
	clear()
	t.Log("Share Test: check to if access token change after revoke is handled correctly")

	_, alice, _, charlie, david, eric, err := helperBigSharePrologue(t)
	if err != nil {
		return
	}
	// ----- END SHARING  -----

	// ----- START REVOKE -----
	err = alice.RevokeFile("fileA", "bob")
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	// ----- END REVOKE

	scrambleDatastore()

	_, err = alice.LoadFile("fileA")
	if err == nil {
		t.Error("Failed to error on corrupted token")
		return
	} else {
		t.Logf("Errored as expected: %s", err)
	}
	_, err = charlie.LoadFile("fileC")
	if err == nil {
		t.Error("Failed to error on corrupted token")
		return
	} else {
		t.Logf("Errored as expected: %s", err)
	}
	_, err = david.LoadFile("fileD")
	if err == nil {
		t.Error("Failed to error on corrupted token")
		return
	} else {
		t.Logf("Errored as expected: %s", err)
	}
	_, err = eric.LoadFile("fileE")
	if err == nil {
		t.Error("Failed to error on corrupted token")
		return
	} else {
		t.Logf("Errored as expected: %s", err)
	}
}

func TestReceiveBadMagicString(t *testing.T) {
	clear()
	_, alice, bob, _, _, _, err := helperBigSharePrologue(t)
	if err != nil {
		return
	}

	file2 := []byte("a new file")
	alice.StoreFile("file2", file2)

	magic, err := alice.ShareFile("file2", "bob")
	if err != nil {
		t.Error("failed to share file", err)
	}

	err = bob.ReceiveFile("filename", "alice", magic[:10])
	if err == nil {
		t.Error("failed to error on bad magic string")
	}

	userlib.DatastoreClear()

}

func TestSwapFileBlockPanic(t *testing.T) {
	clear()

	alice, _ := InitUser("alice", "fubar")

	block0 := []byte("this is the first block")
	block1 := []byte("this is the second block")

	existingKeys := getDSKeys()

	alice.StoreFile("file", block0)

	block0key := getNewestKeys(existingKeys)[0]

	existingKeys = getDSKeys()

	alice.AppendFile("file", block1)

	block1key := getNewestKeys(existingKeys)[0]

	block0cipher, _ := userlib.DatastoreGet(block0key)
	block1cipher, _ := userlib.DatastoreGet(block1key)

	userlib.DatastoreSet(block0key, block1cipher)
	userlib.DatastoreSet(block1key, block0cipher)

	file, err := alice.LoadFile("file")

	if err == nil {
		t.Errorf("Did not detect block swap: %s\n", file)
	} else {
		t.Log("Task failed successfully", err)
	}

}

func TestMissingBlockPanic(t *testing.T) {
	clear()

	alice, _ := InitUser("alice", "fubar")

	block0 := []byte("this is the first block")
	block1 := []byte("this is the second block")
	block2 := []byte("this is the third block")

	alice.StoreFile("file", block0)

	alice.AppendFile("file", block1)

	existingKeys := getDSKeys()

	alice.AppendFile("file", block2)

	block2Key := getNewestKeys(existingKeys)[0]

	userlib.DatastoreDelete(block2Key)

	file, err := alice.LoadFile("file")

	if err == nil {
		t.Errorf("Did not detect block deletion: %s\n", file)
	} else {
		t.Log("Task failed successfully", err)
	}
}

func TestSwapMagicStrings(t *testing.T) {
	clear()

	alice, _ := InitUser("alice", "fubar")
	bob, _ := InitUser("bob", "barfu")

	file1 := []byte("this is file 1")
	alice.StoreFile("file1", file1)

	file2 := []byte("this is file 2")
	alice.StoreFile("file2", file2)

	magic1, _ := alice.ShareFile("file1", "bob")
	magic2, _ := alice.ShareFile("file1", "bob")

	bob.ReceiveFile("bobfile1", "alice", magic2)
	bob.ReceiveFile("bobfile2", "alice", magic1)

}

func TestMissingBlockThenAppendPanic(t *testing.T) {
	clear()

	alice, _ := InitUser("alice", "fubar")

	block0 := []byte("this is the first block")
	block1 := []byte("this is the second block")
	block2 := []byte("this is the third block")

	alice.StoreFile("file", block0)

	existingKeys := getDSKeys()

	alice.AppendFile("file", block1)

	block1Key := getNewestKeys(existingKeys)[0]
	userlib.DatastoreDelete(block1Key)

	alice.AppendFile("file", block2)

	file, err := alice.LoadFile("file")

	if err == nil {
		t.Errorf("Did not detect block deletion: %s\n", file)
	} else {
		t.Log("Task failed successfully", err)
	}
}

//To test corruption of datastore records
func scrambleDatastore() {
	datastore := userlib.DatastoreGetMap()
	keys := make([]userlib.UUID, 0, len(datastore))
	for k := range datastore {
		keys = append(keys, k)
	}
	for _, k := range keys {
		userlib.DatastoreSet(k, []byte("corrupted data"))
	}
}

func getNewestKeys(existingKeys []uuid.UUID) []uuid.UUID {
	keys := []uuid.UUID{}
	datastore := userlib.DatastoreGetMap()
	for dkey := range datastore {
		flag := false
		for _, ekey := range existingKeys {
			if reflect.DeepEqual(dkey, ekey) {
				flag = true
				break
			}
		}
		if !flag {
			keys = append(keys, dkey)
		}
	}
	return keys
}

func getDSKeys() []uuid.UUID {
	keys := []uuid.UUID{}
	datastore := userlib.DatastoreGetMap()
	for dkey := range datastore {
		keys = append(keys, dkey)
	}
	return keys
}
