// htmltrust-key is the offline ceremony CLI for HTMLTrust period-scoped
// signing keys (spec draft §9.10, scheme htmltrust-period-v1). It runs on
// the publisher's offline machine: it holds the master seed and revocation
// anchor key, derives one Ed25519 private key per period on request, and
// renders and checks the identity's DID document. It never runs in CI and
// never touches a live online signer's key.
package main

import (
	"fmt"
	"os"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "htmltrust-key:", err)
		os.Exit(1)
	}
}

const usage = `usage: htmltrust-key <command> [flags]

commands:
  init            start a period-scoped identity (offline)
  derive          deliver one period's private key
  did render      render the DID document from local state
  did check       compare the served DID document against local state
  status          report derivation, publication, and live state
  extend          publish more period public keys ahead
  revoke          strike a range of periods, or rotate the anchor
  rekey           replace the master after a suspected compromise
  recover         rebuild local state from a served DID document
  list sign       sign a hand-edited revocation list with the anchor key
`

func run(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("no command given")
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "init":
		return cmdInit(rest)
	case "derive":
		return cmdDerive(rest)
	case "did":
		if len(rest) == 0 {
			return fmt.Errorf("usage: htmltrust-key did <render|check> [flags]")
		}
		switch rest[0] {
		case "render":
			return cmdDidRender(rest[1:])
		case "check":
			return cmdDidCheck(rest[1:])
		default:
			return fmt.Errorf("unknown did subcommand %q", rest[0])
		}
	case "status":
		return cmdStatus(rest)
	case "extend":
		return cmdExtend(rest)
	case "revoke":
		return cmdRevoke(rest)
	case "rekey":
		return cmdRekey(rest)
	case "recover":
		return cmdRecover(rest)
	case "list":
		if len(rest) == 0 || rest[0] != "sign" {
			return fmt.Errorf("usage: htmltrust-key list sign <file> [flags]")
		}
		return cmdListSign(rest[1:])
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, usage)
		return nil
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q", cmd)
	}
}
