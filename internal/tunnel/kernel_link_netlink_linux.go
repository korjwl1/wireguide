//go:build linux

package tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const kernelNetlinkTimeout = 5 * time.Second

const ifinfomsgLen = 16

type netlinkKernelLinkBackend struct{}

func defaultKernelLinkBackend() (kernelLinkBackend, error) {
	return netlinkKernelLinkBackend{}, nil
}

func ifinfomsg(index int32) []byte {
	b := make([]byte, ifinfomsgLen)
	b[0] = unix.AF_UNSPEC
	binary.NativeEndian.PutUint32(b[4:8], uint32(index))
	return b
}

func (netlinkKernelLinkBackend) execute(typ uint16, flags netlink.HeaderFlags, index int32, attrs func(*netlink.AttributeEncoder)) ([]netlink.Message, error) {
	data := ifinfomsg(index)
	if attrs != nil {
		ae := netlink.NewAttributeEncoder()
		attrs(ae)
		b, err := ae.Encode()
		if err != nil {
			return nil, err
		}
		data = append(data, b...)
	}
	c, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		return nil, fmt.Errorf("opening rtnetlink: %w", err)
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(kernelNetlinkTimeout)); err != nil {
		return nil, fmt.Errorf("setting rtnetlink deadline: %w", err)
	}
	return c.Execute(netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(typ), Flags: netlink.Request | flags},
		Data:   data,
	})
}

func parseKernelLink(m netlink.Message) (kernelLink, error) {
	if len(m.Data) < ifinfomsgLen {
		return kernelLink{}, errors.New("short ifinfomsg")
	}
	link := kernelLink{Index: int32(binary.NativeEndian.Uint32(m.Data[4:8]))}
	ad, err := netlink.NewAttributeDecoder(m.Data[ifinfomsgLen:])
	if err != nil {
		return kernelLink{}, err
	}
	for ad.Next() {
		switch ad.Type() {
		case unix.IFLA_IFNAME:
			link.Name = ad.String()
		case unix.IFLA_IFALIAS:
			link.Alias = ad.String()
		case unix.IFLA_LINKINFO:
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				for nad.Next() {
					if nad.Type() == unix.IFLA_INFO_KIND {
						link.Kind = nad.String()
					}
				}
				return nil
			})
		}
	}
	return link, ad.Err()
}

func (b netlinkKernelLinkBackend) getLink(index int32, name string) (kernelLink, bool, error) {
	var attrs func(*netlink.AttributeEncoder)
	if name != "" {
		attrs = func(ae *netlink.AttributeEncoder) { ae.String(unix.IFLA_IFNAME, name) }
	}
	msgs, err := b.execute(unix.RTM_GETLINK, 0, index, attrs)
	if errors.Is(err, unix.ENODEV) {
		return kernelLink{}, false, nil
	}
	if err != nil {
		return kernelLink{}, false, err
	}
	for _, m := range msgs {
		if m.Header.Type != unix.RTM_NEWLINK {
			continue
		}
		link, err := parseKernelLink(m)
		if err != nil {
			return kernelLink{}, false, err
		}
		if (index > 0 && link.Index != index) || (name != "" && link.Name != name) {
			return kernelLink{}, false, fmt.Errorf("rtnetlink returned link %d %q for query %d %q", link.Index, link.Name, index, name)
		}
		return link, true, nil
	}
	return kernelLink{}, false, nil
}

func (b netlinkKernelLinkBackend) LinkByIndex(index int32) (kernelLink, bool, error) {
	if index <= 0 {
		return kernelLink{}, false, fmt.Errorf("invalid ifindex %d", index)
	}
	return b.getLink(index, "")
}

func (b netlinkKernelLinkBackend) LinkByName(name string) (kernelLink, bool, error) {
	if name == "" {
		return kernelLink{}, false, errors.New("empty interface name")
	}
	return b.getLink(0, name)
}

// CreateWireGuard never omits NLM_F_EXCL: without it a NEWLINK carrying the
// index of an existing device would modify that device.
func (b netlinkKernelLinkBackend) CreateWireGuard(name string, index int32) error {
	if index <= 0 || name == "" {
		return fmt.Errorf("invalid kernel link request %d %q", index, name)
	}
	_, err := b.execute(unix.RTM_NEWLINK, netlink.Acknowledge|netlink.Create|netlink.Excl, index, func(ae *netlink.AttributeEncoder) {
		ae.String(unix.IFLA_IFNAME, name)
		ae.Nested(unix.IFLA_LINKINFO, func(nae *netlink.AttributeEncoder) error {
			nae.String(unix.IFLA_INFO_KIND, kernelLinkKind)
			return nil
		})
	})
	if errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("%w: %w", errKernelLinkExists, err)
	}
	return err
}

// SetAlias deliberately omits IFLA_IFNAME, which would rename the device at
// index instead of selecting it.
func (b netlinkKernelLinkBackend) SetAlias(index int32, alias string) error {
	if index <= 0 {
		return fmt.Errorf("invalid ifindex %d", index)
	}
	_, err := b.execute(unix.RTM_SETLINK, netlink.Acknowledge, index, func(ae *netlink.AttributeEncoder) {
		ae.Bytes(unix.IFLA_IFALIAS, []byte(alias))
	})
	return err
}

func (b netlinkKernelLinkBackend) DeleteIndex(index int32) error {
	if index <= 0 {
		return fmt.Errorf("invalid ifindex %d", index)
	}
	_, err := b.execute(unix.RTM_DELLINK, netlink.Acknowledge, index, nil)
	if errors.Is(err, unix.ENODEV) {
		return fmt.Errorf("%w: %w", errKernelLinkNotFound, err)
	}
	return err
}
