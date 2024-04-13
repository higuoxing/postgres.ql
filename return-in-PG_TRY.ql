/**
 * @name Find suspicious control flow stmt in PG_TRY()
 * @kind problem
 * @problem.severity warning
 * @id postgresql/suspicious-control-flow-stmt-in-pg-try
 */

import cpp

predicate pgTryCatchBlocks(Stmt tryBlock, Stmt catchBlock) {
  exists(IfStmt ifStmt, FunctionCall sigsetjmpCall, BinaryOperation op, Literal zero |
    sigsetjmpCall.getTarget().hasName("__sigsetjmp") and
    ifStmt.getCondition().(BinaryOperation) = op and
    op.getOperator() = "==" and
    op.hasOperands(sigsetjmpCall, zero) and
    /* Reduce false positives. */
    ifStmt.isAffectedByMacro() and
    tryBlock = ifStmt.getThen() and
    catchBlock = ifStmt.getElse()
  )
}

predicate suspiciousReturn(Stmt stmt) { stmt instanceof ReturnStmt }

predicate suspiciousBreak(Stmt stmt, Stmt tryBlock) {
  stmt instanceof BreakStmt and
  not exists(Loop loop |
    loop = tryBlock.getAChild+() and
    loop.getAChild+() = stmt
  ) and
  not exists(SwitchStmt switch |
    switch = tryBlock.getAChild+() and
    switch.getAChild+() = stmt
  )
}

predicate suspiciousContinue(Stmt stmt, Stmt tryBlock) {
  stmt instanceof ContinueStmt and
  not exists(Loop loop |
    loop = tryBlock.getAChild+() and
    loop.getAChild+() = stmt
  )
}

predicate suspiciousGoto(Stmt stmt, Stmt tryBlock) {
  stmt instanceof GotoStmt and
  not exists(LabelStmt label |
    label.getName() = stmt.(GotoStmt).getName() and
    label = tryBlock.getAChild+()
  )
}

from Stmt tryBlock, Stmt suspiciousControlFlowStmt
where
  pgTryCatchBlocks(tryBlock, _) and
  suspiciousControlFlowStmt = tryBlock.getAChild*() and
  (
    suspiciousReturn(suspiciousControlFlowStmt) or
    suspiciousBreak(suspiciousControlFlowStmt, tryBlock) or
    suspiciousContinue(suspiciousControlFlowStmt, tryBlock) or
    suspiciousGoto(suspiciousControlFlowStmt, tryBlock)
  )
select suspiciousControlFlowStmt, "Found suspicious control flow statements in PG_TRY() block"
