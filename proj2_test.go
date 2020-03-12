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

}

func TestShareAppend(t *testing.T) {
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
