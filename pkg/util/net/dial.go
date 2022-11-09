package net

import (
	"context"
	"io"
	"math"
	"net"
	"net/url"

	"github.com/fatedier/frp/pkg/aead/core"
	libdial "github.com/fatedier/golib/net/dial"
	"golang.org/x/net/websocket"
)

func DialHookCustomTLSHeadByte(enableTLS bool, disableCustomTLSHeadByte bool) libdial.AfterHookFunc {
	return func(ctx context.Context, c net.Conn, addr string) (context.Context, net.Conn, error) {
		if enableTLS && !disableCustomTLSHeadByte {
			_, err := c.Write([]byte{byte(FRPTLSHeadByte)})
			if err != nil {
				return nil, nil, err
			}
		}
		return ctx, c, nil
	}
}

func DialHookWebsocket() libdial.AfterHookFunc {
	return func(ctx context.Context, c net.Conn, addr string) (context.Context, net.Conn, error) {
		addr = "ws://" + addr + FrpWebsocketPath
		uri, err := url.Parse(addr)
		if err != nil {
			return nil, nil, err
		}

		origin := "http://" + uri.Host
		cfg, err := websocket.NewConfig(addr, origin)
		if err != nil {
			return nil, nil, err
		}

		conn, err := websocket.NewClient(cfg, c)
		if err != nil {
			return nil, nil, err
		}
		return ctx, conn, nil
	}
}

func WithObscConfigs(key string) []libdial.DialOption {
	return []libdial.DialOption{
		libdial.WithAfterHook(libdial.AfterHook{
			Priority: math.MaxUint64,
			Hook: func(ctx context.Context, c net.Conn, addr string) (context.Context, net.Conn, error) {
				conn, err := core.NewConn(c, key)
				return ctx, conn, err
			},
		}),
		libdial.WithAfterHook(libdial.AfterHook{
			Hook: func(ctx context.Context, c net.Conn, addr string) (context.Context, net.Conn, error) {
				_, err := c.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
				if err != nil {
					return nil, nil, err
				}

				// 读17+8个伪造的HTTP应答, HTTP/1.1 200 OK\r\n
				buf := make([]byte, 17)
				io.ReadAtLeast(c, buf, 17)

				return ctx, c, nil
			},
		}),
	}
}
