package integration

import (
	query "asservat.local/asservat/internal/domain/analysis"
)

const installedRawSyscallQueries = 2
const installedArgumentQueryUnits = installedSyscallProjectionQueries*query.SyscallProjectionQueryUnits + installedRawSyscallQueries*query.SyscallQueryQueryUnits
