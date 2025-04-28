//go:generate gondn_tlv_gen
package trust_schema

import (
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn/spec_2022"
)

type CrossSchemaContent struct {
	//+field:sequence:*SimpleSchemaRule:struct:SimpleSchemaRule
	SimpleSchemaRules []*SimpleSchemaRule `tlv:"0x26C"`
	//+field:sequence:*PrefixSchemaRule:struct:PrefixSchemaRule
	PrefixSchemaRules []*PrefixSchemaRule `tlv:"0x26E"`
}

type SimpleSchemaRule struct {
	//+field:name
	NamePrefix enc.Name `tlv:"0x07"`
	//+field:struct:spec_2022.KeyLocator
	KeyLocator *spec_2022.KeyLocator `tlv:"0x1c"`
}

type PrefixSchemaRule struct {
	//+field:name
	NamePrefix enc.Name `tlv:"0x07"`
}
