package demosec

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/schema"
)

type ContentKey struct {
	ckid    []byte
	keybits []byte
}

// ContentKeyNode handles the generation and fetching of content key, as a proof of concept demo
type ContentKeyNode struct {
	schema.BaseNodeImpl
}

func (n *ContentKeyNode) NodeImplTrait() schema.NodeImpl {
	return n
}

func (n *ContentKeyNode) CastTo(ptr any) any {
	switch ptr.(type) {
	case (*ContentKeyNode):
		return n
	case (*schema.BaseNodeImpl):
		return &(n.BaseNodeImpl)
	default:
		return nil
	}
}

func (n *ContentKeyNode) String() string {
	return fmt.Sprintf("ContentKeyNode (%s)", n.Node)
}

func CreateContentKeyNode(node *schema.Node) schema.NodeImpl {
	ret := &ContentKeyNode{
		BaseNodeImpl: schema.BaseNodeImpl{
			Node:        node,
			OnAttachEvt: &schema.EventTarget{},
			OnDetachEvt: &schema.EventTarget{},
		},
	}
	path, _ := enc.NamePatternFromStr("<contentKeyID>")
	leaf := node.PutNode(path, schema.LeafNodeDesc).Impl().(*schema.LeafNode)
	leaf.ContentType = ndn.ContentTypeKey
	leaf.MustBeFresh = false
	return ret
}

func (n *ContentKeyNode) GenKey(mNode schema.MatchedNode) ContentKey {
	keybits := make([]byte, 32)
	rand.Read(keybits) // Should always succeed
	ckid := make([]byte, 8)
	rand.Read(ckid)

	nameLen := len(mNode.Name)
	ckName := make(enc.Name, nameLen+1)
	copy(ckName, mNode.Name) // Note this does not actually copies the component values
	ckName[nameLen] = enc.Component{Typ: enc.TypeGenericNameComponent, Val: ckid}
	ckMNode := mNode.Refine(ckName)
	ckMNode.Call("Provide", enc.Wire{keybits})

	return ContentKey{ckid, keybits}
}

func (n *ContentKeyNode) Encrypt(mNode schema.MatchedNode, ck ContentKey, content enc.Wire) enc.Wire {
	if len(ck.ckid) != 8 || len(ck.keybits) != 32 {
		log.Error(n, "Invalid content key", "ckid", hex.EncodeToString(ck.ckid))
		return nil
	}

	aescis, err := aes.NewCipher(ck.keybits)
	if err != nil {
		log.Error(n, "Unable to create cipher", "err", err)
		return nil
	}
	iv := make([]byte, aescis.BlockSize())
	rand.Read(iv)
	cip := cipher.NewCBCEncrypter(aescis, iv)
	bs := cip.BlockSize()
	l := content.Length()
	blkn := (int(l) + bs - 1) / bs
	totalLen := blkn * bs
	outbuf := make([]byte, totalLen)
	inbuf := make([]byte, blkn*bs)
	bp := 0
	for _, v := range content {
		bp += copy(inbuf[bp:], v)
	}
	encContent := &EncryptedContent{
		KeyId:         ck.ckid,
		Iv:            iv,
		ContentLength: l,
		CipherText:    enc.Wire{outbuf},
	}
	cip.CryptBlocks(outbuf, inbuf)
	return encContent.Encode()
}

func (n *ContentKeyNode) Decrypt(mNode schema.MatchedNode, encryptedContent enc.Wire) enc.Wire {
	// Note: In real-world implementation, a callback/channel version should be provided
	encContent, err := ParseEncryptedContent(enc.NewWireReader(encryptedContent), true)
	if err != nil {
		log.Error(n, "Malformed encrypted packet")
		return nil
	}

	nameLen := len(mNode.Name)
	ckName := make(enc.Name, nameLen+1)
	copy(ckName, mNode.Name) // Note this does not actually copies the component values
	ckName[nameLen] = enc.Component{Typ: enc.TypeGenericNameComponent, Val: encContent.KeyId}
	ckMNode := mNode.Refine(ckName)

	ckResult := <-ckMNode.Call("NeedChan").(chan schema.NeedResult)
	if ckResult.Status != ndn.InterestResultData {
		log.Warn(n, "Unable to fetch content key", "ck", ckName)
		return nil
	}

	aescis, err := aes.NewCipher(ckResult.Content.Join())
	if err != nil {
		log.Error(n, "Unable to create AES cipher for key", "name", ckResult.Data.Name())
		return nil
	}

	iv := encContent.Iv
	inbuf := encContent.CipherText.Join()
	cip := cipher.NewCBCDecrypter(aescis, iv)
	if len(inbuf)%cip.BlockSize() != 0 {
		log.Error(n, "Input AES buf has a wrong length")
		return nil
	}
	cip.CryptBlocks(inbuf, inbuf)
	return enc.Wire{inbuf[:encContent.ContentLength]}
}

var (
	ContentKeyNodeDesc *schema.NodeImplDesc
)

func init() {
	ContentKeyNodeDesc = &schema.NodeImplDesc{
		ClassName: "ContentKeyNode",
		Properties: map[schema.PropKey]schema.PropertyDesc{
			"Lifetime":      schema.SubNodePropertyDesc("<contentKeyID>", "Lifetime"),
			"Freshness":     schema.SubNodePropertyDesc("<contentKeyID>", "Freshness"),
			"ValidDuration": schema.SubNodePropertyDesc("<contentKeyID>", "ValidDuration"),
		},
		Events: map[schema.PropKey]schema.EventGetter{
			schema.PropOnAttach: schema.DefaultEventTarget(schema.PropOnAttach), // Inherited from base
			schema.PropOnDetach: schema.DefaultEventTarget(schema.PropOnDetach), // Inherited from base
		},
		Functions: map[string]schema.NodeFunc{
			"GenKey": func(mNode schema.MatchedNode, args ...any) any {
				if len(args) > 0 {
					err := fmt.Errorf("ContentKeyNode.GenKey requires 0 arguments but got %d", len(args))
					log.Error(mNode.Node, err.Error())
					return err
				}
				return schema.QueryInterface[*ContentKeyNode](mNode.Node).GenKey(mNode)
			},
			"Encrypt": func(mNode schema.MatchedNode, args ...any) any {
				if len(args) != 2 {
					err := fmt.Errorf("ContentKeyNode.Encrypt requires 2 arguments but got %d", len(args))
					log.Error(mNode.Node, err.Error())
					return err
				}

				ck, ok := args[0].(ContentKey)
				if !ok && args[0] != nil {
					err := ndn.ErrInvalidValue{Item: "ck", Value: args[0]}
					log.Error(mNode.Node, err.Error())
					return err
				}

				content, ok := args[1].(enc.Wire)
				if !ok && args[1] != nil {
					err := ndn.ErrInvalidValue{Item: "content", Value: args[1]}
					log.Error(mNode.Node, err.Error())
					return err
				}

				return schema.QueryInterface[*ContentKeyNode](mNode.Node).Encrypt(mNode, ck, content)
			},
			"Decrypt": func(mNode schema.MatchedNode, args ...any) any {
				if len(args) != 1 {
					err := fmt.Errorf("ContentKeyNode.Decrypt requires 1 arguments but got %d", len(args))
					log.Error(mNode.Node, err.Error())
					return err
				}

				encryptedContent, ok := args[0].(enc.Wire)
				if !ok && args[0] != nil {
					err := ndn.ErrInvalidValue{Item: "encryptedContent", Value: args[0]}
					log.Error(mNode.Node, err.Error())
					return err
				}

				return schema.QueryInterface[*ContentKeyNode](mNode.Node).Decrypt(mNode, encryptedContent)
			},
		},
		Create: CreateContentKeyNode,
	}
	schema.RegisterNodeImpl(ContentKeyNodeDesc)
}
