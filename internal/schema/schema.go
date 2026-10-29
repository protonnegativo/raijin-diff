// Package schema aliases the Raijin Schema from raijin-core, so raijin-diff reads and writes it with
// the same code as the tools it compares.
//
// raijin-diff reads the output of any Raijin tool, so it does not know each tool's finding and group
// fields. It keeps every entry as an ordered list of fields (core.Entry), compares them field by field
// and writes them back in the order the tool wrote them.
package schema

import core "github.com/protonnegativo/raijin-core/schema"

type (
	// Result is the top-level object raijin-diff writes to stdout; its findings and groups are entries.
	Result = core.Result[core.Entry, core.Entry]
	Run    = core.Run
	Entry  = core.Entry
	Field  = core.Field
	Error  = core.Error
	Budget = core.Budget
	// VersionError is what Parse returns for an input written with a newer schema_version.
	VersionError = core.VersionError
)

var (
	Marshal        = core.Marshal
	Parse          = core.Parse
	SeverityRank   = core.SeverityRank
	ConfidenceRank = core.ConfidenceRank
)
