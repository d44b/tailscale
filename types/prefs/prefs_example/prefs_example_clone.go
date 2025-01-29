// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Code generated by tailscale.com/cmd/cloner; DO NOT EDIT.

package prefs_example

import (
	"net/netip"

	"tailscale.com/drive"
	"tailscale.com/tailcfg"
	"tailscale.com/types/opt"
	"tailscale.com/types/persist"
	"tailscale.com/types/prefs"
	"tailscale.com/types/preftype"
)

// Clone makes a deep copy of Prefs.
// The result aliases no memory with the original.
func (src *Prefs) Clone() *Prefs {
	if src == nil {
		return nil
	}
	dst := new(Prefs)
	*dst = *src
	dst.AdvertiseTags = *src.AdvertiseTags.Clone()
	dst.AdvertiseRoutes = *src.AdvertiseRoutes.Clone()
	dst.DriveShares = *src.DriveShares.Clone()
	dst.Persist = src.Persist.Clone()
	return dst
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _PrefsCloneNeedsRegeneration = Prefs(struct {
	ControlURL             prefs.Item[string]
	RouteAll               prefs.Item[bool]
	ExitNodeID             prefs.Item[tailcfg.StableNodeID]
	ExitNodeIP             prefs.Item[netip.Addr]
	ExitNodePrior          tailcfg.StableNodeID
	ExitNodeAllowLANAccess prefs.Item[bool]
	CorpDNS                prefs.Item[bool]
	RunSSH                 prefs.Item[bool]
	RunWebClient           prefs.Item[bool]
	WantRunning            prefs.Item[bool]
	LoggedOut              prefs.Item[bool]
	ShieldsUp              prefs.Item[bool]
	AdvertiseTags          prefs.List[string]
	Hostname               prefs.Item[string]
	NotepadURLs            prefs.Item[bool]
	ForceDaemon            prefs.Item[bool]
	Egg                    prefs.Item[bool]
	AdvertiseRoutes        prefs.List[netip.Prefix]
	NoSNAT                 prefs.Item[bool]
	NoStatefulFiltering    prefs.Item[opt.Bool]
	NetfilterMode          prefs.Item[preftype.NetfilterMode]
	OperatorUser           prefs.Item[string]
	ProfileName            prefs.Item[string]
	AutoUpdate             AutoUpdatePrefs
	AppConnector           AppConnectorPrefs
	PostureChecking        prefs.Item[bool]
	NetfilterKind          prefs.Item[string]
	DriveShares            prefs.StructList[*drive.Share]
	AllowSingleHosts       prefs.Item[marshalAsTrueInJSON]
	Persist                *persist.Persist
}{})

// Clone makes a deep copy of AutoUpdatePrefs.
// The result aliases no memory with the original.
func (src *AutoUpdatePrefs) Clone() *AutoUpdatePrefs {
	if src == nil {
		return nil
	}
	dst := new(AutoUpdatePrefs)
	*dst = *src
	return dst
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _AutoUpdatePrefsCloneNeedsRegeneration = AutoUpdatePrefs(struct {
	Check prefs.Item[bool]
	Apply prefs.Item[opt.Bool]
}{})

// Clone makes a deep copy of AppConnectorPrefs.
// The result aliases no memory with the original.
func (src *AppConnectorPrefs) Clone() *AppConnectorPrefs {
	if src == nil {
		return nil
	}
	dst := new(AppConnectorPrefs)
	*dst = *src
	return dst
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _AppConnectorPrefsCloneNeedsRegeneration = AppConnectorPrefs(struct {
	Advertise prefs.Item[bool]
}{})
