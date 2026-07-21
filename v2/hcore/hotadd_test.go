package hcore

// hotadd_test.go — интеграционный гард hot-add (AddOutbound/RemoveOutbound) на
// ЖИВОМ box: та самая цепочка, что дергает soft-switch при смене подписки.
//
// Root cause 2026-07-22: servers из контейнерных подписок хранятся app'ом как
// одиночный sing-box outbound/endpoint JSON, а parseConfigContent ронял этот
// класс с «[SingboxParser] unmarshal error: EOF» (cycle-баг обёртки) — hot-add
// падал в пересборку там, где полная сборка работала. До фикса parser.go этот
// тест падал на первом же AddOutbound с JSON-контентом.
//
// Запуск:
//
//	cd core && TAGS=$(sed -n 's/^BASE_TAGS=//p' Makefile|head -1) \
//	  go test -tags "$TAGS" ./v2/hcore/ -run TestHotAdd -v

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/twilgate/inhive-core/v2/config"
)

func startHotAddTestInstance(t *testing.T) *InhiveInstance {
	t.Helper()
	ctx := libbox.BaseContext(nil)
	baseConfig := `{"outbounds":[
		{"type":"direct","tag":"direct"},
		{"type":"selector","tag":"select","outbounds":["direct"],"default":"direct"}
	]}`
	opts, err := config.ParseConfig(ctx, &config.ReadOptions{Content: baseConfig}, false, nil, true)
	if err != nil {
		t.Fatalf("base config parse: %v", err)
	}
	bringUpCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	inst, err := startRawSideInstance(context.Background(), bringUpCtx, opts)
	if err != nil {
		t.Fatalf("bring-up: %v", err)
	}
	t.Cleanup(func() { _ = inst.Close() })
	return inst
}

func selectorMembers(t *testing.T, inst *InhiveInstance) []string {
	t.Helper()
	ob, loaded := inst.Box().Outbound().Outbound("select")
	if !loaded {
		t.Fatal("selector 'select' not found in live box")
	}
	sel, ok := ob.(*group.Selector)
	if !ok {
		t.Fatalf("'select' is not a *group.Selector: %T", ob)
	}
	return sel.All()
}

// TestHotAdd_SingboxJSONOutbound — hot-add сервера, чья идентичность = одиночный
// sing-box outbound JSON (ровно контент «~ Netherlands | TCP» из device-diag:
// сервер контейнерной подписки). До фикса: gRPC-ошибка «add outbound: parse:
// [SingboxParser] unmarshal error: EOF» → fallback на пересборку.
func TestHotAdd_SingboxJSONOutbound(t *testing.T) {
	inst := startHotAddTestInstance(t)

	content := `{"type":"vless","server":"1.2.3.4","server_port":443,` +
		`"uuid":"0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9","flow":"xtls-rprx-vision",` +
		`"tls":{"enabled":true,"server_name":"example.com",` +
		`"utls":{"enabled":true,"fingerprint":"chrome"},` +
		`"reality":{"enabled":true,"public_key":"eLVH-wqasU5th1LgWxkL82y_wCp1dSApnc_E0kDp40s","short_id":"6ba85179"}}}`

	resp, err := inst.AddOutbound(&AddOutboundRequest{
		Content:      content,
		SelectorTags: []string{"select"},
		TagOverride:  "~ Netherlands | TCP",
	})
	if err != nil {
		t.Fatalf("AddOutbound(single sing-box JSON) failed: %v", err)
	}
	if resp.OutboundTag != "~ Netherlands | TCP" {
		t.Fatalf("OutboundTag: got %q, want tag override", resp.OutboundTag)
	}
	if _, loaded := inst.Box().Outbound().Outbound("~ Netherlands | TCP"); !loaded {
		t.Fatal("hot-added outbound not found in live box")
	}
	if members := selectorMembers(t, inst); !slices.Contains(members, "~ Netherlands | TCP") {
		t.Fatalf("selector members %v do not contain hot-added tag", members)
	}

	if _, err := inst.RemoveOutbound(&RemoveOutboundRequest{OutboundTag: "~ Netherlands | TCP"}); err != nil {
		t.Fatalf("RemoveOutbound failed: %v", err)
	}
	if _, loaded := inst.Box().Outbound().Outbound("~ Netherlands | TCP"); loaded {
		t.Fatal("outbound still in live box after remove")
	}
	if members := selectorMembers(t, inst); slices.Contains(members, "~ Netherlands | TCP") {
		t.Fatalf("selector members %v still contain removed tag", members)
	}
}

// TestHotAdd_ShareLinkOutbound — гард горячего пути для share-link класса
// (работал и до фикса; не сломать).
func TestHotAdd_ShareLinkOutbound(t *testing.T) {
	inst := startHotAddTestInstance(t)

	resp, err := inst.AddOutbound(&AddOutboundRequest{
		Content:      "trojan://trojanpass@example.com:443?type=ws&path=%2Fws&security=tls&sni=example.com#Trojan%20WS",
		SelectorTags: []string{"select"},
		TagOverride:  "Trojan WS",
	})
	if err != nil {
		t.Fatalf("AddOutbound(share-link) failed: %v", err)
	}
	if resp.OutboundTag != "Trojan WS" {
		t.Fatalf("OutboundTag: got %q, want %q", resp.OutboundTag, "Trojan WS")
	}
	if members := selectorMembers(t, inst); !slices.Contains(members, "Trojan WS") {
		t.Fatalf("selector members %v do not contain hot-added tag", members)
	}
}

// TestHotAdd_WireguardEndpointJSON — hot-add wireguard: sing-box 1.13+ держит
// его в endpoints[] (создание через EndpointManager, тоже started-режим);
// OutboundManager.Outbound(tag) резолвит endpoint fallback'ом, поэтому в
// селекторе он полноправный член. До фикса: тот же EOF (JSON-класс), а до
// расширения AddOutbound — «no usable outbound in content».
func TestHotAdd_WireguardEndpointJSON(t *testing.T) {
	inst := startHotAddTestInstance(t)

	content := `{"type":"wireguard","address":["172.16.0.2/32"],` +
		`"private_key":"lkVixBsvwS1FLSKVNOc2rBG+hqiIFVYc8l+5kp5JWtQ=",` +
		`"peers":[{"address":"162.159.192.1","port":2408,` +
		`"public_key":"xQZfukJm8IeGNMqUlahMNUCAaOAJfWRFDeLkl4M8utw=",` +
		`"allowed_ips":["0.0.0.0/0","::/0"]}]}`

	resp, err := inst.AddOutbound(&AddOutboundRequest{
		Content:      content,
		SelectorTags: []string{"select"},
		TagOverride:  "WG Node",
	})
	if err != nil {
		t.Fatalf("AddOutbound(wireguard endpoint JSON) failed: %v", err)
	}
	if resp.OutboundTag != "WG Node" {
		t.Fatalf("OutboundTag: got %q, want %q", resp.OutboundTag, "WG Node")
	}
	if _, loaded := inst.Box().Endpoint().Get("WG Node"); !loaded {
		t.Fatal("hot-added endpoint not found in EndpointManager")
	}
	if _, loaded := inst.Box().Outbound().Outbound("WG Node"); !loaded {
		t.Fatal("endpoint tag not resolvable through OutboundManager fallback")
	}
	if members := selectorMembers(t, inst); !slices.Contains(members, "WG Node") {
		t.Fatalf("selector members %v do not contain hot-added endpoint", members)
	}

	if _, err := inst.RemoveOutbound(&RemoveOutboundRequest{OutboundTag: "WG Node"}); err != nil {
		t.Fatalf("RemoveOutbound(endpoint) failed: %v", err)
	}
	if _, loaded := inst.Box().Endpoint().Get("WG Node"); loaded {
		t.Fatal("endpoint still in EndpointManager after remove")
	}
	if members := selectorMembers(t, inst); slices.Contains(members, "WG Node") {
		t.Fatalf("selector members %v still contain removed endpoint", members)
	}
}
