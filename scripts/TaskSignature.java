// Applies function prototypes to an already-analysed program and re-exports
// the artifacts the change can be seen in. Run against the *kept* project of
// an existing job:
//
//   analyzeHeadless <proj> ghidrarest -process -noanalysis \
//       -postScript RestScript.java signature <outdir> <opsFile> <resultFile> [timeoutSec]
//
// Why not just re-run the export task: retyping one function must not cost a
// full re-analysis and a full re-decompile. Analysis is already on disk in the
// project; only the decompiler output of the retyped function and of its
// callers can change, so only those are rewritten.
//
// ops.tsv columns: <address key><TAB><prototype>[<TAB><calling convention>]
// The prototype is C, exactly what Ghidra's "Edit Function Signature" takes:
//   long make_secret(byte *secret)
// The convention is optional and is the same dropdown that dialog has. It is
// applied separately because Ghidra's C parser accepts `__cdecl` in the text
// and then throws it away -- leaving a function whose storage is locked while
// its convention is still "unknown", which is what produces the decompiler's
// "parameter storage is locked" warning.
//
// Artifacts rewritten under <outdir>:
//   functions.json            whole file (a listing walk, no decompilation)
//   conventions.json          what this program's compiler spec accepts
//   decompiled/<addr>.json    only the retyped functions and their callers
//
// Deliberately NOT rewritten: decompiled/index.json (its `length` field goes
// stale for the rewritten functions and nothing reads it for correctness),
// disasm/* (instructions do not change), summary.json (counts do not change).
//
//@category ghidra-rest
import java.io.File;
import java.io.Writer;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.FunctionRenameOption;
import ghidra.app.util.cparser.C.CParserUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;

public class TaskSignature implements Task {

	@Override
	public String name() {
		return "signature";
	}

	@Override
	public String usage() {
		return "<outdir> <opsFile> <resultFile> [decompileTimeoutSec]";
	}

	@Override
	public String logTag() {
		return "ApplySignature";
	}

	private Ctx c;
	private int decompileTimeout = 60;

	@Override
	public void run(Ctx ctx, String[] args) throws Exception {
		this.c = ctx;
		if (args.length < 2) {
			throw new IllegalArgumentException("usage: RestScript signature " + usage());
		}
		File opsFile = new File(args[0]);
		File resultFile = new File(args[1]);
		if (args.length > 2) {
			decompileTimeout = Integer.parseInt(args[2]);
		}

		Program p = c.program;
		List<RestOps.Op> ops = RestOps.read(opsFile, 3);
		c.log("program=" + p.getName() + " ops=" + ops.size());

		// Functions whose decompilation can change: the retyped ones, plus
		// every caller -- a caller's C text names the callee's parameters and
		// assigns its return value, so it is wrong the moment the callee is
		// retyped. Callers of callers are not followed: their text refers to
		// the direct callee only.
		Set<Address> affected = new LinkedHashSet<Address>();

		for (RestOps.Op op : ops) {
			apply(p, op, affected);
		}

		RestOps.writeResult(resultFile, ops);

		// functions.json carries the stored signature, return type and
		// parameter list of every function, so it is rewritten whole even if a
		// single op landed. It is a listing walk: no decompiler involved.
		RestFunc.exportAll(c, p, false);
		exportConventions(p);

		int redecompiled = RestDecomp.writeSubset(c, p, affected, decompileTimeout);

		c.log("done applied=" + RestOps.countOk(ops) + "/" + ops.size() +
			" redecompiled=" + redecompiled);
	}

	// ------------------------------------------------------------- applying

	private void apply(Program p, RestOps.Op op, Set<Address> affected) {
		String proto = op.col(0);
		String cc = op.col(1);

		Address entry;
		try {
			entry = p.getAddressFactory().getAddress(op.key);
		}
		catch (Exception e) {
			op.message = "cannot parse address " + op.key;
			return;
		}
		if (entry == null) {
			op.message = "cannot parse address " + op.key;
			return;
		}
		Function f = p.getListing().getFunctionAt(entry);
		if (f == null) {
			op.message = "no function at " + op.key;
			return;
		}
		op.before = f.getSignature().getPrototypeString();

		FunctionDefinitionDataType def;
		try {
			// handleExceptions=false: the true branch pops a Swing error
			// dialog, which in headless means the parse failure is swallowed
			// and the caller only sees null. We want the parser's own message.
			def = CParserUtils.parseSignature(null, p, detachReturnStars(proto), false);
		}
		catch (Throwable t) {
			op.message = "cannot parse prototype: " + RestOps.rootMessage(t);
			return;
		}
		if (def == null) {
			op.message = "cannot parse prototype: not a function signature";
			return;
		}

		int tx = p.startTransaction("ghidra-rest: set signature " + op.key);
		boolean applied = false;
		try {
			// NO_CHANGE: the name in the prototype is ignored. Renaming is a
			// separate concern and guttex keeps its own rename layer; a retype
			// silently renaming the function would fight it.
			// preserveCallingConvention=true for the same reason -- the caller
			// asked about types, not about the ABI.
			ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(entry, def,
				SourceType.USER_DEFINED, true, false, DataTypeConflictHandler.DEFAULT_HANDLER,
				FunctionRenameOption.NO_CHANGE);
			applied = cmd.applyTo(p, c.monitor);
			if (!applied) {
				op.message = cmd.getStatusMsg() == null ? "Ghidra refused the signature"
						: cmd.getStatusMsg();
			}
			else if (!cc.isEmpty()) {
				// After the signature, not before: applying a signature can reset
				// storage, and the convention is what decides how that storage is
				// laid out.
				//
				// setCallingConvention accepts a name the program has never heard
				// of and stores it verbatim, which leaves the decompiler printing
				// "Unknown calling convention: __cdecl" over a function that looks
				// like it was configured. Check first and name the alternatives.
				if (p.getFunctionManager().getCallingConvention(cc) == null) {
					throw new IllegalArgumentException("this program has no calling convention \"" +
						cc + "\"; it accepts " + joinConventions(p));
				}
				f.setCallingConvention(cc);
			}
		}
		catch (Throwable t) {
			// Also reached when the convention name is rejected *after* the
			// signature landed. Half an edit is worse than none, so roll the
			// whole transaction back.
			applied = false;
			op.message = RestOps.rootMessage(t);
		}
		finally {
			p.endTransaction(tx, applied);
		}
		if (!applied) {
			return;
		}

		op.ok = true;
		op.message = f.getSignature().getPrototypeString();
		affected.add(entry);
		for (Function caller : f.getCallingFunctions(c.monitor)) {
			affected.add(caller.getEntryPoint());
		}
	}

	// Ghidra's C parser binds a '*' that touches the function name to the
	// declarator rather than to the return type. FunctionRenameOption.NO_CHANGE
	// then discards the name -- and the pointer goes with it, so "long *f(void)"
	// applies as "long f(void)" with no error anywhere. Detaching the stars from
	// the name keeps them on the return type: "long * f(void)".
	//
	// Only the text before the parameter list is touched, so a function-pointer
	// return ("void (*f)(int)") is left exactly as written.
	private static String detachReturnStars(String proto) {
		int paren = proto.indexOf('(');
		if (paren < 0) {
			return proto;
		}
		String head = proto.substring(0, paren);
		String tail = proto.substring(paren);
		String fixed = head.replaceAll("\\*\\s*([A-Za-z_][A-Za-z0-9_]*)\\s*$", "* $1");
		return fixed + tail;
	}

	private static String joinConventions(Program p) {
		StringBuilder b = new StringBuilder();
		for (String n : p.getFunctionManager().getCallingConventionNames()) {
			if (b.length() > 0) {
				b.append(", ");
			}
			b.append(n);
		}
		return b.toString();
	}

	// The names this program will accept, written every run so a job analysed
	// before summary.json carried them still ends up with a list the UI can
	// offer. Cheap: it is a handful of strings off the compiler spec.
	private void exportConventions(Program p) throws Exception {
		Writer w = c.open("conventions.json");
		try {
			w.write("[");
			boolean first = true;
			for (String n : p.getFunctionManager().getCallingConventionNames()) {
				if (!first) {
					w.write(",");
				}
				first = false;
				w.write(RestJson.quoted(n));
			}
			w.write("]");
		}
		finally {
			w.close();
		}
	}
}
