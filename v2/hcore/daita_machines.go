package hcore

// RESERVED(2026-09-23, Nikita): DAITA / maybenot (этот файл, initDaita в
// buildconfighelper.go, опции daita-*, сабмодуль maybenot) — не удалять, см.
// аудит фундамента §5.5 (app/docs/foundation/2026-09-19-audit-and-program.md).

// DefaultDaitaMachines contains the bundled maybenot machine definitions
// for DAITA (Defence Against Traffic Analysis).
// Source: Mullvad VPN dist-assets/maybenot_machines
// These machines implement FRONT-like padding strategies that resist
// ML-based website fingerprinting attacks.
const DefaultDaitaMachines = `02eNptjLsNwCAQQ++yQRZImTJlRIdYBDEJA7ERJQtQ0iC+dxSIJ1mWLcv5TsLH9wMmF4KLqwkRAawk2yPR00CHX3V3j1GziWvE09NBBWg9Fjk=
02eNqFjLENwCAMBP8hC2SJlKnTsVr2zBKUaVACNgiBEJxknex/Oezv9fjjRCF8mXLY4pAEbpeFJFlFqJBGA7PqWQ3spCer4l3rnvGDH6+FGlE=
02eNqFjDkOgDAMBL056PkEJTVdvsY/+URKmojDmwiBUDyStbJ35DLuy5anWRrlqLTDcA0AkTXVkDt01ZAHwLFwludZeMsLLILlRRax4+lKcnrnl/8HJzqIIG0=
02eNpdjr0LQVEYxt9zGES5o4myKVksFM45lEHKx0LJYDAZ5C+QRTHIaGETViYDKYPp3ijFYLj3KkmGK2WwuVwiv3rrrafnA1Jm16ijKBQ+6NRDGPJ2E0Xe6YnAD0hFD9nm/ObIHumlv4imZ3Mm8DwvtaxB0Jy1IUex0pYIIB30lhuCYkYvwW6nQFSV41R1L8vkmwlgEOONVvEaYt1SwLhdhxn8gdBgEfXU7RFmzeR9YtPPxrbqOVkLsd29XJhIJfbqRomGheLcYUWeFgxQodrq9wcP1E88/w==`
