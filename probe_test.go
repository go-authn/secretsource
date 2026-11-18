//go:build probe

package secretsource

import (
	"context"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"
)

// TestProbe replays our client against a THROWAWAY KeePassXC socket, one step
// at a time (KPX_SOCK=path KPX_STEP=1..5, KPX_URL=url for step 5). Never point
// it at a real database. Step 5 is associate (someone must accept the dialog)
// followed by get-logins for KPX_URL.
func TestProbe(t *testing.T) {
	sock := os.Getenv("KPX_SOCK")
	if sock == "" {
		t.Skip("KPX_SOCK not set")
	}
	step, _ := strconv.Atoi(os.Getenv("KPX_STEP"))
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	nc, err := (&net.Dialer{}).DialContext(ctx, "unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	k, err := newConn(ctx, nc)
	if err != nil {
		t.Fatalf("step 1 (change-public-keys): %v", err)
	}
	defer k.close()
	t.Log("step 1 ok")
	if step < 2 {
		return
	}
	hash, err := k.databaseHash()
	if err != nil {
		t.Fatalf("step 2 (get-databasehash): %v", err)
	}
	t.Logf("step 2 ok: %s", hash)
	if step < 5 {
		return
	}
	idPub, _, _ := box.GenerateKey(randReader)
	var res struct {
		ID string `json:"id"`
	}
	if err := k.call("associate", map[string]any{"key": b64(k.pub[:]), "idKey": b64(idPub[:])}, &res); err != nil {
		t.Fatalf("associate: %v", err)
	}
	t.Logf("associated as %q", res.ID)
	var lr struct {
		Entries []map[string]any `json:"entries"`
	}
	t.Logf("sending get-logins for %q", os.Getenv("KPX_URL"))
	err = k.call("get-logins", map[string]any{"url": os.Getenv("KPX_URL"), "keys": []map[string]string{{"id": res.ID, "key": b64(idPub[:])}}}, &lr)
	t.Logf("get-logins: %v (%d entries)", err, len(lr.Entries))
}
