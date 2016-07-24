package spread

import (
	"fmt"
	"gopkg.in/yaml.v2"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"
)

func QEMU(b *Backend) Provider {
	return &qemu{b}
}

type qemu struct {
	backend *Backend
}

type qemuServer struct {
	l       *qemu
	d       qemuServerData
	qemuCmd *exec.Cmd
}

type qemuServerData struct {
	Name    string
	Backend string
	System  string
	Address string
	Port    int
}

func (s *qemuServer) String() string {
	return fmt.Sprintf("%s:%s", s.l.backend.Name, s.d.System)
}

func (s *qemuServer) Provider() Provider {
	return s.l
}

func (s *qemuServer) Address() string {
	return s.d.Address
}

func (s *qemuServer) Port() int {
	return s.d.Port
}

func (s *qemuServer) System() string {
	return s.d.System
}

func (s *qemuServer) ReuseData() []byte {
	data, err := yaml.Marshal(&s.d)
	if err != nil {
		panic(err)
	}
	return data
}

func (s *qemuServer) Discard() error {
	err := s.qemuCmd.Process.Kill()
	if err != nil {
		return fmt.Errorf("cannot discard qemu: %v", err)
	}
	return nil
}

func (l *qemu) Backend() *Backend {
	return l.backend
}

func (l *qemu) Reuse(data []byte, password string) (Server, error) {
	server := &qemuServer{}
	err := yaml.Unmarshal(data, &server.d)
	if err != nil {
		return nil, fmt.Errorf("cannot unmarshal qemu reuse data: %v", err)
	}
	server.l = l
	return server, nil
}

func (server *qemuServer) waitReady() error {
	seconds := 30
	for i := 0; i < 30; i++ {
		addr := fmt.Sprintf("%s:%d", server.Address(), server.Port())
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}
		conn.Close()
		return nil
	}
	return fmt.Errorf("cannot connect to %s:%d after %d seconds", server.Address(), server.Port(), seconds)
}

func (l *qemu) Allocate(system string, password string, keep bool) (Server, error) {
	// FIXME: keep does not currently work because the runner
	//        wants to (re)connect to address only (and does not
	//        take the port into consideration). Either
	//        extend how reuse is done or just merge address+port
	if keep {
		return nil, fmt.Errorf("keep not supported yet")
	}

	// FIXME: lets hope we get a free one ;)
	localPort := 20000 + rand.Intn(10000)

	path := os.Getenv("SPREAD_QEMU_VM")
	if path == "" {
		path = filepath.Join(os.Getenv("HOME"), "VM", system)
	}

	cmd := exec.Command(
		"kvm",
		"-nographic",
		"-snapshot",
		"-m", "1500",
		"-net", "nic",
		"-net", fmt.Sprintf("user,hostfwd=tcp::%d-:22", localPort),
		path)
	err := cmd.Start()
	if err != nil {
		return nil, &FatalError{fmt.Errorf("cannot launch qemu: %v", err)}
	}

	server := &qemuServer{
		l:       l,
		qemuCmd: cmd,
		d: qemuServerData{
			System:  system,
			Address: "localhost",
			Port:    localPort,
			// Name? Backend?
		},
	}

	printf("Waiting for qemu %s to have an address...", system)
	if err := server.waitReady(); err != nil {
		return nil, fmt.Errorf("cannot connect to qemu %s:%d", server.Address(), server.Port())
	}

	err = server.addRootUserSSH(password)
	if err != nil {
		server.Discard()
		return nil, err
	}

	printf("Allocated %s.", server.String())
	return server, nil
}

func (l *qemuServer) sshConnect() (*ssh.Client, error) {
	user := os.Getenv("SPREAD_QEMU_USER")
	if user == "" {
		user = "ubuntu"
	}
	pw := os.Getenv("SPREAD_QEMU_PASSWORD")
	if pw == "" {
		pw = "ubuntu"
	}

	config := &ssh.ClientConfig{
		User:    user,
		Auth:    []ssh.AuthMethod{ssh.Password(pw)},
		Timeout: 10 * time.Second,
	}
	addr := fmt.Sprintf("%s:%d", l.Address(), l.Port())
	return ssh.Dial("tcp", addr, config)
}

func (server *qemuServer) addRootUserSSH(password string) error {
	sshc, err := server.sshConnect()
	if err != nil {
		return fmt.Errorf("cannot connect to %s:%d: %s", server.Address(), server.Port(), err)
	}
	defer sshc.Close()

	// enable ssh root login, set root password and restart sshd
	cmds := []string{
		`sudo sed -i 's/\(PermitRootLogin\|PasswordAuthentication\)\>.*/\1 yes/' /etc/ssh/sshd_config`,
		fmt.Sprintf(`sudo /bin/bash -c "%s"`, fmt.Sprintf("echo root:%s | chpasswd", password)),
		"sudo systemctl reload sshd",
	}
	for _, cmd := range cmds {
		session, err := sshc.NewSession()
		if err != nil {
			return err
		}
		output, err := session.CombinedOutput(cmd)
		session.Close()
		if err != nil {
			return fmt.Errorf("cannot prepare sshd in qemu container %q: %v", server.Port(), outputErr(output, err))
		}
	}
	return nil
}
