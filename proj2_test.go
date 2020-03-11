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
	t.Log("Got user", u)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
}

func TestGetUser(t *testing.T) {
	clear()
	t.Log("GetUser Test")
	userlib.SetDebugStatus(true)

	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	t.Log("Got user", u)

	u1, err := InitUser("alice1", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	t.Log("Got user", u1)

	nu1, err := GetUser("alice", "fubar")
	t.Log("Got user again", nu1)

	nu2, err := GetUser("alice1", "fubar")
	t.Log("Got user again", nu2)

	if err != nil || nu1.Username != "alice" || nu2.Username != "alice1" {
		t.Error("Failed to Get User")
		return
	}

}

func TestStorage(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := make([]byte, MAX_BLOCK_SIZE*20)
	v[MAX_BLOCK_SIZE*15+1] = 10
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

func TestAppend(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := make([]byte, MAX_BLOCK_SIZE*20)
	v[MAX_BLOCK_SIZE*15+1] = 10
	u.StoreFile("file1", v)

	newData := make([]byte, MAX_BLOCK_SIZE*10)
	newData[MAX_BLOCK_SIZE*3+12] = 30

	u.AppendFile("file1", newData)

	v_new, _ := u.LoadFile("file1")

	if !reflect.DeepEqual(v_new, append(v, newData...)) {
		t.Error("Appending failed")
		return
	}

}

func TestInvalidFile(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err2 := u.LoadFile("this file does not exist")
	if err2 == nil {
		t.Error("Downloaded a ninexistent file", err2)
		return
	}
}

func TestShare(t *testing.T) {
	clear()
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

	newData := make([]byte, MAX_BLOCK_SIZE*20)
	newData[MAX_BLOCK_SIZE*10+14] = 9

	u2.StoreFile("file2", newData)

	newData2, err := u2.LoadFile("file2")
	newData1, err := u.LoadFile("file1")

	if !reflect.DeepEqual(newData1, newData2) {
		t.Error("Shared file is not the same", newData1, newData2)
		return
	}

}

func TestRevokeAllChildren(t *testing.T) {

	alicebranch := Sharebranch{
		Parent:   "alice",
		Children: []string{"bob", "charlie"},
	}
	bobbranch := Sharebranch{
		Parent:   "bob",
		Children: []string{"david"},
	}
	charliebranch := Sharebranch{
		Parent:   "charlie",
		Children: []string{"eric", "fred"},
	}
	davidbranch := Sharebranch{
		Parent:   "david",
		Children: []string{"george"},
	}
	ericbranch := Sharebranch{
		Parent:   "eric",
		Children: []string{},
	}
	fredbranch := Sharebranch{
		Parent:   "fred",
		Children: []string{},
	}
	georgebranch := Sharebranch{
		Parent:   "george",
		Children: []string{},
	}

	var dummyMetadata Metadata
	dummyMetadata.Sharetree = []Sharebranch{alicebranch, bobbranch, charliebranch, davidbranch, ericbranch, fredbranch, georgebranch}

	dummyMetadata.Sharetree = RevokeAllChildren(dummyMetadata.Sharetree, "bob")

	expectedRemaining := []string{"alice", "charlie", "eric", "fred"}
	for i := 0; i < len(dummyMetadata.Sharetree); i++ {
		if dummyMetadata.Sharetree[i].Parent != expectedRemaining[i] {
			t.Error("Did not revoke correctly", dummyMetadata.Sharetree, expectedRemaining)
		}
	}
}
