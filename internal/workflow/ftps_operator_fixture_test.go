//go:build ftpsfixture

package workflow

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestActualFTPSOperatorFactoryPassesTheUnchangedConnectionValidator(t *testing.T) {
	private, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"cert.pem", "producer.token"} {
		if err := os.WriteFile(filepath.Join(private, name), []byte("inert factory contract stand-in"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, mode := range []string{"explicit", "implicit"} {
		// Invoke the actual Python request factory,not a separately maintained
		// JSON imitation. No peer,credential login,database or socket starts.
		command := exec.CommandContext(t.Context(), "python3", "-c", `import json,sys
from pathlib import Path
sys.path.insert(0,str(Path.cwd()/"scripts"))
import ftps_collection_operator as operator
print(json.dumps(operator.connection(Path(sys.argv[1]),Path(sys.argv[1]),sys.argv[2],21000,{"tenant_id":"10000000-1111-4111-8111-111111111111","partner_id":"10000001-1111-4111-8111-111111111111"})))`, private, mode)
		command.Dir = filepath.Join("..", "..")
		command.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
		raw, err := command.Output()
		if err != nil {
			t.Fatal("actual operator request factory failed")
		}
		var request ConnectionRequest
		if Decode(raw, &request) != nil || request.FTPS == nil || !request.FTPS.Valid(request.Directory) {
			t.Fatalf("actual %s operator source request fails ordinary immutable connection validation", mode)
		}
		if request.FTPS.Valid("/") || request.FTPS.Valid(request.FTPS.StagingDirectory) {
			t.Fatal("factory repair relaxed the staging/final tree separation rule")
		}
	}
}
