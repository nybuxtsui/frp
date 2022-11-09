// Copyright 2019 fatedier, fatedier@gmail.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package net

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"time"

	"github.com/fatedier/frp/pkg/aead/core"
	"github.com/fatedier/frp/pkg/util/log"
	gnet "github.com/fatedier/golib/net"
)

var FRPTLSHeadByte = 0x17
var FRPObscHeadByte = 0x47

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

func randStringBytesMaskImpr(n int) string {
	b := make([]byte, n)
	// A rand.Int63() generates 63 random bits, enough for letterIdxMax letters!
	for i, cache, remain := n-1, rand.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = rand.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}
	return string(b)
}

func CheckAndEnableTLSServerConnWithTimeout(
	c net.Conn, tlsConfig *tls.Config, tlsOnly bool, timeout time.Duration, obscKey string,
) (out net.Conn, isTLS bool, custom bool, err error) {
	sc, r := gnet.NewSharedConnSize(c, 2)
	buf := make([]byte, 1)
	var n int

	_ = c.SetReadDeadline(time.Now().Add(timeout))
	defer c.SetReadDeadline(time.Time{})

	n, err = r.Read(buf)
	if err != nil {
		return
	}

	switch {
	case n == 1 && int(buf[0]) == FRPTLSHeadByte:
		out = tls.Server(c, tlsConfig)
		isTLS = true
		custom = true
	case n == 1 && int(buf[0]) == FRPObscHeadByte:
		// 再读17个伪造的http请求, ET / HTTP/1.1\r\n\r\n
		buf = make([]byte, 17)
		n, err = io.ReadAtLeast(c, buf, 17)
		if n != 17 {
			err = errors.New("bad header for obsc")
			return
		}
		// 生成随机密钥
		c.Write([]byte("HTTP/1.1 200 OK\r\n"))

		log.Info("obsckey=" + obscKey)
		out, err = core.NewConn(c, obscKey)
		if err != nil {
			return
		}
		isTLS = false
		custom = true
	case n == 1 && int(buf[0]) == 0x16:
		out = tls.Server(sc, tlsConfig)
		isTLS = true
	default:
		if tlsOnly {
			err = fmt.Errorf("non-TLS connection received on a TlsOnly server")
			return
		}
		out = sc
	}
	return
}
