package ipsec

import (
	"fmt"
	"github.com/vishvananda/netlink"
	"net"
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

	if err := netlink.XfrmStateFlush(0); err != nil {
		return err
	}

	if err := netlink.XfrmPolicyFlush(); err != nil {
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
	if err := ipsec.addPolicy(local, remote, outReqID, netlink.XFRM_DIR_OUT); err != nil {
		return err
	}

	// Inbound SA and policy
	inReqID := ipsec.nextReqID
	ipsec.nextReqID++
	if _, err := ipsec.addSA(remote, local, inReqID, inKey); err != nil {
		return err
	}
	if err := ipsec.addPolicy(remote, local, inReqID, netlink.XFRM_DIR_IN); err != nil {
		return err
	}

	return nil
}

func (ipsec *IPsec) addSA(src, dst net.IP, reqID ReqID, key []byte) (SPID, error) {
	spid := ipsec.nextSPID
	ipsec.nextSPID++

	state := &netlink.XfrmState{
		Src:   src,
		Dst:   dst,
		Spi:   int(spid),
		Reqid: int(reqID),
		Proto: netlink.XFRM_PROTO_ESP,
		Mode:  netlink.XFRM_MODE_TUNNEL,
		Aead: &netlink.XfrmStateAlgo{
			Name:   "rfc4106(gcm(aes))",
			Key:    key,
			IcvLen: 96}}

	if err := netlink.XfrmStateAdd(state); err != nil {
		return 0, err
	}

	return spid, nil
}

func (ipsec *IPsec) addPolicy(src, dst net.IP, reqID ReqID, dir netlink.Dir) error {

	tmpl := netlink.XfrmPolicyTmpl{
		Src:   src,
		Dst:   dst,
		Reqid: int(reqID),
		Proto: netlink.XFRM_PROTO_ESP,
		Mode:  netlink.XFRM_MODE_TUNNEL}

	policy := &netlink.XfrmPolicy{
		Src:     &net.IPNet{src, net.IPv4Mask(0xff, 0xff, 0xff, 0xff)},
		Dst:     &net.IPNet{dst, net.IPv4Mask(0xff, 0xff, 0xff, 0xff)},
		Proto:   netlink.XFRM_PROTO_UDP,
		DstPort: 6784,
		Dir:     dir,
		Tmpls:   []netlink.XfrmPolicyTmpl{tmpl}}

	if err := netlink.XfrmPolicyAdd(policy); err != nil {
		return err
	}

	return nil
}
