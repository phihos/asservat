// Synthetic local receiver. No Kubernetes/OIDC/KMS/SQL/S3 production authority.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/streamingaead"
	"github.com/tink-crypto/tink-go/v2/tink"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Permit struct {
	PID   int
	Start uint64
}
type Config struct {
	Mode, Dir, NativeDir string
	Expires              int64
	Permits              []Permit
}
type Report struct {
	PID, HelperPID, UID, Signal                   int
	Start                                         uint64
	HelperCgroup, Reason, NativeSHA, CipherSHA    string
	Bytes                                         int64
	Accepted, Complete, NativeVerified, Finalized bool
}

func statStart(pid int) (uint64, error) {
	b, e := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if e != nil {
		return 0, e
	}
	i := strings.LastIndex(string(b), ")")
	if i < 0 {
		return 0, fmt.Errorf("stat")
	}
	f := strings.Fields(string(b[i+1:]))
	if len(f) <= 19 {
		return 0, fmt.Errorf("stat length")
	}
	return strconv.ParseUint(f[19], 10, 64)
}
func main() {
	if _, e := os.Stat("/root/ASSERVAT_DISPOSABLE_VM"); e != nil {
		panic("VM guard absent")
	}
	b, e := os.ReadFile(os.Args[1])
	if e != nil {
		panic(e)
	}
	var cfg Config
	if e = json.Unmarshal(b, &cfg); e != nil {
		panic(e)
	}
	if len(cfg.Permits) > 32 {
		panic("permit bound")
	}
	keys := map[int]tink.StreamingAEAD{}
	perms := map[int]uint64{}
	for _, p := range cfg.Permits {
		if _, e = os.Stat(filepath.Join(cfg.Dir, fmt.Sprint(p.PID)+".spent")); e == nil {
			continue
		}
		h, e := keyset.NewHandle(streamingaead.AES256GCMHKDF1MBKeyTemplate())
		if e != nil {
			panic(e)
		}
		a, e := streamingaead.New(h)
		if e != nil {
			panic(e)
		}
		keys[p.PID] = a
		perms[p.PID] = p.Start
	}
	os.Remove("/run/asservat-crash/socket")
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: "/run/asservat-crash/socket", Net: "unix"})
	if e != nil {
		panic(e)
	}
	defer listener.Close()
	os.Chmod("/run/asservat-crash/socket", 0600)
	os.WriteFile(filepath.Join(cfg.Dir, "ready"), []byte("ready"), 0600)
	var mu sync.Mutex
	for {
		conn, e := listener.AcceptUnix()
		if e != nil {
			return
		}
		go func() {
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(4 * time.Second))
			r := Report{Reason: "handshake"}
			raw, e := conn.SyscallConn()
			if e != nil {
				return
			}
			var peer *syscall.Ucred
			raw.Control(func(fd uintptr) { peer, e = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED) })
			if e != nil || peer == nil || peer.Uid != 0 {
				return
			}
			r.HelperPID = int(peer.Pid)
			line, e := bufio.NewReaderSize(conn, 128).ReadSlice('\n')
			if e != nil {
				return
			}
			if _, e = fmt.Sscanf(string(line), "%d %d %d %d", &r.PID, &r.Start, &r.Signal, &r.UID); e != nil {
				return
			}
			cg, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", r.HelperPID))
			r.HelperCgroup = string(cg)
			save := func() {
				b, _ := json.MarshalIndent(r, "", "  ")
				path := filepath.Join(cfg.Dir, fmt.Sprintf("%d.json", r.PID))
				if os.WriteFile(path+".tmp", b, 0600) == nil {
					os.Rename(path+".tmp", path)
				}
			}
			defer func() { r.Finalized = true; save() }()
			if cfg.Mode == "stallHandshake" {
				time.Sleep(3 * time.Second)
				r.Reason = "stalled-handshake"
				return
			}
			mu.Lock()
			a, found := keys[r.PID]
			start := perms[r.PID]
			liveStart, err := statStart(r.PID)
			if !found || start != r.Start || liveStart != r.Start || err != nil || time.Now().UnixMilli() >= cfg.Expires {
				mu.Unlock()
				r.Reason = "no-current-prepared-permit"
				conn.Write([]byte{0})
				return
			}
			spent, e := os.OpenFile(filepath.Join(cfg.Dir, fmt.Sprint(r.PID)+".spent"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if e != nil {
				mu.Unlock()
				r.Reason = "spent-or-uncertain"
				conn.Write([]byte{0})
				return
			}
			_, e = spent.Write([]byte("spent; never rehydrate keys or refund on restart\n"))
			if e == nil {
				e = spent.Sync()
			}
			spent.Close()
			dir, de := os.Open(cfg.Dir)
			if de == nil {
				de = dir.Sync()
				dir.Close()
			}
			delete(keys, r.PID)
			delete(perms, r.PID)
			mu.Unlock()
			if e != nil || de != nil {
				r.Reason = "spend-persistence-failed"
				return
			}
			r.Accepted = true
			save()
			if _, e = conn.Write([]byte{1}); e != nil {
				return
			}
			os.WriteFile(filepath.Join(cfg.Dir, fmt.Sprint(r.PID)+".ack"), []byte("accepted"), 0600)
			if cfg.Mode == "stallRead" {
				time.Sleep(3 * time.Second)
				r.Reason = "stalled-read"
				return
			}
			path := filepath.Join(cfg.Dir, fmt.Sprint(r.PID)+".enc")
			f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if e != nil {
				r.Reason = "spool-failed"
				return
			}
			defer f.Close()
			aad := []byte(fmt.Sprintf("synthetic-vm-core/%d/%d", r.PID, r.Start))
			w, e := a.NewEncryptingWriter(f, aad)
			if e != nil {
				return
			}
			h := sha256.New()
			buf := make([]byte, 65536)
			header := make([]byte, 4)
			r.Reason = "interrupted"
			for {
				if _, e = io.ReadFull(conn, header); e != nil {
					break
				}
				n := binary.BigEndian.Uint32(header)
				if n == 0 {
					r.Complete = true
					r.Reason = "complete"
					break
				}
				if n > 65536 || r.Bytes+int64(n) > 16<<20 {
					r.Reason = "bound"
					break
				}
				if _, e = io.ReadFull(conn, buf[:n]); e != nil {
					break
				}
				if _, e = w.Write(buf[:n]); e != nil {
					r.Reason = "encryption-write"
					break
				}
				h.Write(buf[:n])
				r.Bytes += int64(n)
			}
			if e = w.Close(); e != nil {
				r.Complete = false
				r.Reason = "encryption-close"
			}
			if e = f.Sync(); e != nil {
				r.Complete = false
				r.Reason = "spool-sync"
			}
			f.Close()
			r.NativeSHA = hex.EncodeToString(h.Sum(nil))
			cipher, e := os.Open(path)
			if e != nil {
				return
			}
			ch := sha256.New()
			io.Copy(ch, cipher)
			cipher.Close()
			r.CipherSHA = hex.EncodeToString(ch.Sum(nil))
			if r.Complete {
				cipher, e = os.Open(path)
				if e != nil {
					return
				}
				defer cipher.Close()
				reader, e := a.NewDecryptingReader(cipher, aad)
				if e != nil {
					return
				}
				native, e := os.OpenFile(filepath.Join(cfg.NativeDir, fmt.Sprint(r.PID)+".core"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if e != nil {
					return
				}
				nh := sha256.New()
				n, e := io.Copy(io.MultiWriter(native, nh), io.LimitReader(reader, (16<<20)+1))
				native.Close()
				r.NativeVerified = e == nil && n == r.Bytes && hex.EncodeToString(nh.Sum(nil)) == r.NativeSHA
				if r.NativeVerified {
					conn.Write([]byte{2})
				} else {
					r.Reason = "native-verification-failed"
				}
			}
		}()
	}
}
