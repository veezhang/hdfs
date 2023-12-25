package rpc

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"

	hadoop "github.com/colinmarc/hdfs/v2/internal/protocol/hadoop_common"
	"github.com/colinmarc/hdfs/v2/internal/sasl"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/spnego"
	krbtypes "github.com/jcmturner/gokrb5/v8/types"
)

const saslRpcCallId = -33

var (
	errKerberosNotSupported = errors.New("kerberos authentication not supported by namenode")
	krbSPNHost              = regexp.MustCompile(`\A[^/]+/(_HOST)([@/]|\z)`)
)

func (c *NamenodeConnection) doKerberosHandshake() error {
	// Start negotiation, and get the list of supported mechanisms in reply.
	// spew.Printf("doKerberosHandshake: start\n")
	err := c.writeSaslRequest(&hadoop.RpcSaslProto{
		State: hadoop.RpcSaslProto_NEGOTIATE.Enum(),
	})
	if err != nil {
		// spew.Printf("doKerberosHandshake: writeSaslRequest NEGOTIATE failed %v\n", err)
		return err
	}

	resp, err := c.readSaslResponse(hadoop.RpcSaslProto_NEGOTIATE)
	if err != nil {
		// spew.Printf("doKerberosHandshake: readSaslResponse NEGOTIATE failed %v\n", err)
		return err
	}

	// spew.Printf("doKerberosHandshake: readSaslResponse NEGOTIATE successfully. \n    resp: %+v\n", resp)

	var krbAuth, tokenAuth *hadoop.RpcSaslProto_SaslAuth
	for _, m := range resp.GetAuths() {
		switch *m.Method {
		case "KERBEROS":
			krbAuth = m
		case "TOKEN":
			tokenAuth = m
		default:
		}
	}

	if krbAuth == nil {
		// spew.Printf("doKerberosHandshake: errKerberosNotSupported\n")
		return errKerberosNotSupported
	}

	// Get a ticket from Kerberos, and send the initial token to the namenode.
	token, sessionKey, err := c.getKerberosTicket()
	if err != nil {
		// spew.Printf("doKerberosHandshake: getKerberosTicket failed %v\n", err)
		return err
	}

	// spew.Printf("doKerberosHandshake: getKerberosTicket successfully. \n    token %+v, \n    sessionKey %+v\n", token, sessionKey)

	if tokenAuth != nil {
		challenge, err := sasl.ParseChallenge(tokenAuth.Challenge)
		if err != nil {
			// spew.Printf("doKerberosHandshake: ParseChallenge failed %v\n", err)
			return err
		}

		// Some versions of HDP 3.x expect us to pick the highest Qop, and
		// return a malformed response otherwise.
		sort.Sort(challenge.Qop)
		qop := challenge.Qop[0]

		// spew.Printf("doKerberosHandshake: ParseChallenge successfully. \n    challenge %+v\n", challenge)

		switch qop {
		case sasl.QopPrivacy, sasl.QopIntegrity:
			// Switch to SASL RPC handler
			c.transport = &saslTransport{
				basicTransport: basicTransport{
					clientID: c.ClientID,
				},
				sessionKey: sessionKey,
				privacy:    qop == sasl.QopPrivacy,
			}
		case sasl.QopAuthentication:
			// No special transport is required.
		default:
			return errors.New("unexpected QOP in challenge")
		}
	}

	err = c.writeSaslRequest(&hadoop.RpcSaslProto{
		State: hadoop.RpcSaslProto_INITIATE.Enum(),
		Token: token.MechTokenBytes,
		Auths: []*hadoop.RpcSaslProto_SaslAuth{krbAuth},
	})
	if err != nil {
		// spew.Printf("doKerberosHandshake: writeSaslRequest INITIATE failed %v\n", err)
		return err
	}

	// In response, we get a server token to verify.
	resp, err = c.readSaslResponse(hadoop.RpcSaslProto_CHALLENGE)
	if err != nil {
		// spew.Printf("doKerberosHandshake: readSaslResponse CHALLENGE failed %v\n", err)
		return err
	}

	// spew.Printf("doKerberosHandshake: readSaslResponse CHALLENGE successfully.\n    resp %+v\n", resp)

	var signedBytes []byte
	if len(resp.GetToken()) > 0 && resp.GetToken()[0] == 0x60 {
		// spew.Printf("doKerberosHandshake: WrapTokenV1\n")

		var nnToken gssapi.WrapTokenV1
		if err = nnToken.Unmarshal(resp.GetToken(), true); err != nil {
			// spew.Printf("doKerberosHandshake: WrapTokenV1 Unmarshal failed %v\n", err)
			return err
		}

		// spew.Printf("doKerberosHandshake: WrapTokenV1 Unmarshal successfully.\n    nnToken %+v\n", nnToken)

		_, err = nnToken.Verify(sessionKey, keyusage.GSSAPI_ACCEPTOR_SIGN)
		if err != nil {
			// spew.Printf("doKerberosHandshake: WrapTokenV1 Verify failed %v\n", err)
			return fmt.Errorf("invalid server token: %s", err)
		}

		signed, err := gssapi.NewInitiatorWrapTokenV1(&nnToken, sessionKey)
		if err != nil {
			// spew.Printf("doKerberosHandshake: NewInitiatorWrapTokenV1 failed %v\n", err)
			return err
		}

		signedBytes, err = signed.Marshal(sessionKey)
		if err != nil {
			// spew.Printf("doKerberosHandshake: WrapTokenV1 Marshal failed %v\n", err)
			return err
		}
	} else {
		// spew.Printf("doKerberosHandshake: WrapToken\n")

		var nnToken gssapi.WrapToken
		err = nnToken.Unmarshal(resp.GetToken(), true)
		if err != nil {
			// spew.Printf("doKerberosHandshake: WrapToken Unmarshal failed %v\n", err)
			return err
		}

		_, err = nnToken.Verify(sessionKey, keyusage.GSSAPI_ACCEPTOR_SEAL)
		if err != nil {
			// spew.Printf("doKerberosHandshake: WrapToken Verify failed %v\n", err)
			return fmt.Errorf("invalid server token: %s", err)
		}

		// Sign the payload and send it back to the namenode.
		// TODO: Make sure we can support what is required based on what's in the
		// payload.
		signed, err := gssapi.NewInitiatorWrapToken(nnToken.Payload, sessionKey)
		if err != nil {
			// spew.Printf("doKerberosHandshake: NewInitiatorWrapToken failed %v\n", err)
			return err
		}

		signedBytes, err = signed.Marshal()
		if err != nil {
			// spew.Printf("doKerberosHandshake: WrapToken Marshal failed %v\n", err)
			return err
		}
	}

	err = c.writeSaslRequest(&hadoop.RpcSaslProto{
		State: hadoop.RpcSaslProto_RESPONSE.Enum(),
		Token: signedBytes,
	})
	if err != nil {
		// spew.Printf("doKerberosHandshake: writeSaslRequest RESPONSE failed %v\n", err)
		return err
	}

	// Read the final response. If it's a SUCCESS, then we're done here.
	_, err = c.readSaslResponse(hadoop.RpcSaslProto_SUCCESS)
	if err != nil {
		// spew.Printf("doKerberosHandshake: readSaslResponse SUCCESS failed %v\n", err)
	}
	return err
}

func (c *NamenodeConnection) writeSaslRequest(req *hadoop.RpcSaslProto) error {
	rrh := newRPCRequestHeader(saslRpcCallId, c.ClientID)
	packet, err := makeRPCPacket(rrh, req)
	if err != nil {
		return err
	}

	_, err = c.conn.Write(packet)
	return err
}

func (c *NamenodeConnection) readSaslResponse(expectedState hadoop.RpcSaslProto_SaslState) (*hadoop.RpcSaslProto, error) {
	rrh := &hadoop.RpcResponseHeaderProto{}
	resp := &hadoop.RpcSaslProto{}
	err := readRPCPacket(c.conn, rrh, resp)
	if err != nil {
		return nil, err
	} else if int32(rrh.GetCallId()) != saslRpcCallId {
		return nil, errors.New("unexpected sequence number")
	} else if rrh.GetStatus() != hadoop.RpcResponseHeaderProto_SUCCESS {
		return nil, &NamenodeError{
			method:    "sasl",
			message:   rrh.GetErrorMsg(),
			code:      int(rrh.GetErrorDetail()),
			exception: rrh.GetExceptionClassName(),
		}
	} else if resp.GetState() != expectedState {
		return nil, fmt.Errorf("unexpected SASL state: %s", resp.GetState().String())
	}

	return resp, nil
}

// getKerberosTicket returns an initial kerberos negotiation token and the
// paired session key, along with an error if any occured.
func (c *NamenodeConnection) getKerberosTicket() (spnego.NegTokenInit, krbtypes.EncryptionKey, error) {
	host, _, _ := net.SplitHostPort(c.host.address)
	spn := replaceSPNHostWildcard(c.kerberosServicePrincipleName, host)

	ticket, key, err := c.kerberosClient.GetServiceTicket(spn)
	if err != nil {
		return spnego.NegTokenInit{}, key, err
	}

	token, err := spnego.NewNegTokenInitKRB5(c.kerberosClient, ticket, key)
	return token, key, err
}

// replaceSPNHostWildcard substitutes the special string '_HOST' in the given
// SPN for the given (current) host.
func replaceSPNHostWildcard(spn, host string) string {
	res := krbSPNHost.FindStringSubmatchIndex(spn)
	if res == nil || res[2] == -1 {
		return spn
	}

	return spn[:res[2]] + host + spn[res[3]:]
}
