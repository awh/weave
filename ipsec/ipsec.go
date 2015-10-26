package ipsec

import (
	"encoding/hex"
	"fmt"
	"net"
	"os/exec"
	"sync"
)

const IPCmd = "/sbin/ip"

type SPID uint32
type ReqID uint32

type IPsec struct {
	sync.RWMutex
	nextReqID ReqID
	nextSPID  SPID
}

func NewIPsec() *IPsec {
	return &IPsec{
		nextReqID: 0x0001,
		nextSPID:  0x0001,
	}
}

func (ipsec *IPsec) Flush() error {
	ipsec.Lock()
	defer ipsec.Unlock()

	fmt.Println("Flushing IPsec policy and state databases")

	if err := exec.Command(IPCmd, "xfrm", "state", "flush").Run(); err != nil {
		return err
	}

	if err := exec.Command(IPCmd, "xfrm", "policy", "flush").Run(); err != nil {
		return err
	}

	return nil
}

func (ipsec *IPsec) ProtectConnection(local, remote net.IP, inKey, outKey []byte) error {
	ipsec.Lock()
	defer ipsec.Unlock()

	fmt.Println("Protecting connection", local, remote, inKey, outKey)

	// Outbound SA and policy
	outReqID := ipsec.nextReqID
	ipsec.nextReqID++
	if _, err := ipsec.addSA(local, remote, outReqID, outKey); err != nil {
		return err
	}
	if err := ipsec.addPolicy(local, remote, outReqID, "out"); err != nil {
		return err
	}

	// Inbound SA and policy
	inReqID := ipsec.nextReqID
	ipsec.nextReqID++
	if _, err := ipsec.addSA(remote, local, inReqID, inKey); err != nil {
		return err
	}
	if err := ipsec.addPolicy(remote, local, inReqID, "in"); err != nil {
		return err
	}

	return nil
}

func (ipsec *IPsec) addSA(src, dst net.IP, reqID ReqID, key []byte) (SPID, error) {
	spid := ipsec.nextSPID
	ipsec.nextSPID++

	cmd := exec.Command(IPCmd, "xfrm",
		"state", "add",
		"src", fmt.Sprintf("%v/32", src),
		"dst", fmt.Sprintf("%v/32", dst),
		"proto", "esp",
		"spi", fmt.Sprintf("0x%x", spid),
		"reqid", fmt.Sprintf("0x%x", reqID),
		"mode", "tunnel",
		"aead", "rfc4106(gcm(aes))",
		fmt.Sprintf("0x%s", hex.EncodeToString(key)),
		"96")

	fmt.Println(cmd)

	if err := cmd.Run(); err != nil {
		return 0, err
	}

	return spid, nil
}

func (ipsec *IPsec) addPolicy(src, dst net.IP, reqID ReqID, direction string) error {
	cmd := exec.Command(IPCmd, "xfrm",
		"policy", "add",
		"src", fmt.Sprintf("%v/32", src),
		"dst", fmt.Sprintf("%v/32", dst),
		"proto", "udp",
		"dport", "6784",
		"dir", direction,
		"tmpl",
		"src", fmt.Sprintf("%v", src),
		"dst", fmt.Sprintf("%v", dst),
		"proto", "esp",
		"reqid", fmt.Sprintf("0x%x", reqID),
		"mode", "tunnel")

	fmt.Println(cmd)

	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}
