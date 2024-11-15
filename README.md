# vmnet-proxy

A TCP/UDP proxy for macOS utilizing `vmnet.framework`

## Requirements

- macOS 10.10 or later.

## Example usage

```
$ go build .
$ sudo ./vmnet-proxy tcp:2222:192.168.1.5:22
$ sudo ./vmnet-proxy -iface en1 tcp:5901:192.168.1.5:5900
$ sudo ./vmnet-proxy tcp:443:1.1.1.1:443 tcp:80:1.1.1.1:80
```

## TODO
- IPv6 support
- DHCP support for IPv4

## Credits

Credits to https://github.com/alessiodionisi/qemu-vmnet for the native code in `pkg/vmnet/`.
