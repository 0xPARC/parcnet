package pod

import (
	"archive/tar"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
)

type PodEntries map[string]PodValue

type Pod struct {
	Entries         PodEntries `json:"entries"`
	Signature       string     `json:"signature"`
	SignerPublicKey string     `json:"signerPublicKey"`
}

type podCommandRequest struct {
	Cmd        string                 `json:"cmd"`
	PrivateKey string                 `json:"private_key"`
	Entries    map[string]interface{} `json:"entries"`
}

const STABLE_TAG = "v0.2.4"

func validatePrivateKeyHex(pk string) error {
	if len(pk) != 64 {
		return fmt.Errorf("private key must be 64 hex characters (32 bytes), got length %d", len(pk))
	}
	decoded, err := hex.DecodeString(pk)
	if err != nil {
		return fmt.Errorf("private key '%s' isn't valid hex: %v", pk, err)
	}
	if len(decoded) != 32 {
		return fmt.Errorf("decoded private key is %d bytes, expected 32", len(decoded))
	}
	return nil
}

var downloadOnce sync.Once
var downloadErr error
var podWorkerPath string // Final path to the extracted pod_worker binary

func dispatchRustCommand(req podCommandRequest) (*Pod, string, error) {
	binPath, err := getOrDownloadPodWorker()
	if err != nil {
		return nil, "", err
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal request: %w", err)
	}

	cmd := exec.Command(binPath)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, "", fmt.Errorf("failed to get stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, "", fmt.Errorf("failed to get stdout: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, "", fmt.Errorf("failed to start process: %w", err)
	}

	if _, err := stdin.Write(reqBytes); err != nil {
		return nil, "", fmt.Errorf("failed writing to stdin: %w", err)
	}
	stdin.Close()

	outBytes, err := io.ReadAll(stdout)
	if werr := cmd.Wait(); werr != nil {
		return nil, "", fmt.Errorf("rust process error: %w", werr)
	}
	if err != nil {
		return nil, "", fmt.Errorf("failed reading stdout: %w", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(outBytes, &raw); err != nil {
		return nil, "", fmt.Errorf("failed unmarshal raw: %w\nOutput: %s", err, string(outBytes))
	}

	remarshaled, err := json.Marshal(raw)
	if err != nil {
		return nil, "", fmt.Errorf("failed re-marshal: %w", err)
	}

	var pod Pod
	if err := json.Unmarshal(remarshaled, &pod); err != nil {
		return nil, "", fmt.Errorf("failed final unmarshal Pod: %w", err)
	}

	jsonPodBytes, err := json.Marshal(pod)
	if err != nil {
		return &pod, "", fmt.Errorf("failed to marshal JSONPOD: %w", err)
	}

	return &pod, string(jsonPodBytes), nil
}

func getOrDownloadPodWorker() (string, error) {
	downloadOnce.Do(func() {
		osName, err := resolveArtifactName(runtime.GOOS, runtime.GOARCH)
		if err != nil {
			downloadErr = err
			return
		}

		tarURL := fmt.Sprintf(
			"https://github.com/0xPARC/parcnet/releases/download/%s/pod_worker-%s.tar.gz",
			STABLE_TAG,
			osName,
		)
		fmt.Println("Downloading pod_worker from", tarURL)

		tmpDir, err := os.MkdirTemp("", "pod_worker_bin")
		if err != nil {
			downloadErr = fmt.Errorf("failed to create temp dir: %w", err)
			return
		}

		tarPath := filepath.Join(tmpDir, "pod_worker.tar.gz")

		if err := downloadFile(tarURL, tarPath); err != nil {
			downloadErr = fmt.Errorf("failed to download artifact: %w", err)
			return
		}

		if err := extractTarGz(tarPath, tmpDir); err != nil {
			downloadErr = fmt.Errorf("failed to extract pod_worker tarball: %w", err)
			return
		}

		binName := "pod_worker"
		if runtime.GOOS == "windows" {
			binName = "pod_worker.exe"
		}
		finalBin := filepath.Join(tmpDir, binName)

		if err := os.Chmod(finalBin, 0755); err != nil {
			downloadErr = fmt.Errorf("failed to chmod pod_worker: %w", err)
			return
		}

		podWorkerPath = finalBin
	})

	if downloadErr != nil {
		return "", downloadErr
	}
	return podWorkerPath, nil
}

// Maps (GOOS, GOARCH) to the "os-name" used in the final artifact filename.
// E.g., if GOOS="linux" and GOARCH="amd64", we get "Linux-x86_64".
func resolveArtifactName(goos, goarch string) (string, error) {
	combos := map[[2]string]string{
		{"freebsd", "amd64"}: "FreeBSD-x86_64",
		{"linux", "amd64"}:   "Linux-gnu-x86_64",
		{"linux", "arm64"}:   "Linux-gnu-aarch64",
		{"linux", "arm"}:     "Linux-gnu-arm",
		{"linux", "386"}:     "Linux-gnu-i686",
		{"linux", "ppc"}:     "Linux-gnu-powerpc",
		{"linux", "ppc64"}:   "Linux-gnu-powerpc64",
		{"linux", "ppc64le"}: "Linux-gnu-powerpc64le",
		{"linux", "riscv64"}: "Linux-gnu-riscv64",
		{"linux", "s390x"}:   "Linux-gnu-s390x",
		{"windows", "arm64"}: "Windows-msvc-aarch64",
		{"windows", "386"}:   "Windows-msvc-i686",
		{"windows", "amd64"}: "Windows-msvc-x86_64",
		{"darwin", "amd64"}:  "macOS-x86_64",
		{"darwin", "arm64"}:  "macOS-arm64",
	}
	key := [2]string{goos, goarch}
	if val, ok := combos[key]; ok {
		return val, nil
	}
	return "", fmt.Errorf("unsupported GOOS/GOARCH combination: %s/%s", goos, goarch)
}

func downloadFile(url, destination string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code %d when downloading %s", resp.StatusCode, url)
	}

	out, err := os.Create(destination)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func extractTarGz(src, dest string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			// no more files
			break
		}
		if err != nil {
			return err
		}

		path := filepath.Join(dest, hdr.Name)
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(path, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				return err
			}
			outFile, err := os.Create(path)
			if err != nil {
				return err
			}
			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				return err
			}
			outFile.Close()
		default:
			// skip special file types
		}
	}

	return nil
}
