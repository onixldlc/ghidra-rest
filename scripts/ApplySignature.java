// Applies function prototypes to an already-analysed program and re-exports
// the artifacts the change can be seen in. Run by analyzeHeadless as a
// -postScript against the *kept* project of an existing job:
//
//   analyzeHeadless <proj> ghidrarest -process <file> -noanalysis \
//       -postScript ApplySignature.java <outdir> <opsFile> <resultFile> [timeoutSec]
//
// Why a second script instead of re-running ExportJSON: retyping one function
// must not cost a full re-analysis and a full re-decompile. Analysis is
// already on disk in the project; only the decompiler output of the retyped
// function and of its callers can change, so only those are rewritten.
//
// opsFile is TAB separated, one op per line, `#` comments and blanks ignored:
//   <address key><TAB><prototype>[<TAB><calling convention>]
// The prototype is C, exactly what Ghidra's "Edit Function Signature" takes:
//   long make_secret(byte *secret)
// The convention is optional and is the same dropdown that dialog has. It is
// applied separately because Ghidra's C parser accepts `__cdecl` in the text
// and then throws it away -- leaving a function whose storage is locked while
// its convention is still "unknown", which is what produces the decompiler's
// "parameter storage is locked" warning.
//
// resultFile is TAB separated, one line per op, written even when the op fails:
//   <address key><TAB>ok<TAB><before><TAB><after>
//   <address key><TAB>error<TAB><before><TAB><message>
// Tabs and newlines inside a field are turned into spaces, so a reader can
// split on TAB without quoting rules. The server owns the durable record of
// which prototypes are set; this script is a pure "apply these, tell me what
// happened" step and holds no state of its own.
//
// Artifacts rewritten under <outdir>:
//   functions.json            whole file (a listing walk, no decompilation)
//   decompiled/<addr>.json    only the retyped functions and their callers
//
// Deliberately NOT rewritten: decompiled/index.json (its `length` field goes
// stale for the rewritten functions and nothing reads it for correctness),
// disasm/* (instructions do not change), summary.json (counts do not change).
//
//@category ghidra-rest

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.FunctionRenameOption;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.cparser.C.CParserUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.StackFrame;
import ghidra.program.model.symbol.SourceType;

public class ApplySignature extends GhidraScript {

	private int decompileTimeout = 60;

	private File outDir;

	private static class Op {
		String key;
		String proto;
		String cc = "";
		String before = "";
		boolean ok;
		String message = "";
	}

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 3) {
			throw new IllegalArgumentException(
				"usage: ApplySignature <outdir> <opsFile> <resultFile> [decompileTimeoutSec]");
		}
		outDir = new File(args[0]);
		File opsFile = new File(args[1]);
		File resultFile = new File(args[2]);
		if (args.length > 3) {
			decompileTimeout = Integer.parseInt(args[3]);
		}

		Program p = currentProgram;
		List<Op> ops = readOps(opsFile);
		println("ApplySignature: program=" + p.getName() + " ops=" + ops.size());

		// Functions whose decompilation can change: the retyped ones, plus
		// every caller -- a caller's C text names the callee's parameters and
		// assigns its return value, so it is wrong the moment the callee is
		// retyped. Callers of callers are not followed: their text refers to
		// the direct callee only.
		Set<Address> affected = new LinkedHashSet<Address>();

		for (Op op : ops) {
			apply(p, op, affected);
		}

		writeResult(resultFile, ops);

		// functions.json carries the stored signature, return type and
		// parameter list of every function, so it is rewritten whole even if a
		// single op landed. It is a listing walk: no decompiler involved.
		exportFunctions(p);
		exportConventions(p);

		if (!affected.isEmpty()) {
			exportDecompiledSubset(p, affected);
		}

		println("ApplySignature: done applied=" + countOk(ops) + "/" + ops.size() +
			" redecompiled=" + affected.size());
	}

	private static int countOk(List<Op> ops) {
		int n = 0;
		for (Op o : ops) {
			if (o.ok) {
				n++;
			}
		}
		return n;
	}

	// ------------------------------------------------------------- applying

	private void apply(Program p, Op op, Set<Address> affected) {
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
			def = CParserUtils.parseSignature(null, p, detachReturnStars(op.proto), false);
		}
		catch (Throwable t) {
			op.message = "cannot parse prototype: " + rootMessage(t);
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
			applied = cmd.applyTo(p, monitor);
			if (!applied) {
				op.message = cmd.getStatusMsg() == null ? "Ghidra refused the signature"
						: cmd.getStatusMsg();
			}
			else if (!op.cc.isEmpty()) {
				// After the signature, not before: applying a signature can reset
				// storage, and the convention is what decides how that storage is
				// laid out.
				//
				// setCallingConvention accepts a name the program has never heard
				// of and stores it verbatim, which leaves the decompiler printing
				// "Unknown calling convention: __cdecl" over a function that looks
				// like it was configured. Check first and name the alternatives.
				if (p.getFunctionManager().getCallingConvention(op.cc) == null) {
					throw new IllegalArgumentException("this program has no calling convention \"" +
						op.cc + "\"; it accepts " + joinConventions(p));
				}
				f.setCallingConvention(op.cc);
			}
		}
		catch (Throwable t) {
			// Also reached when the convention name is rejected *after* the
			// signature landed. Half an edit is worse than none, so roll the
			// whole transaction back.
			applied = false;
			op.message = rootMessage(t);
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
		for (Function c : f.getCallingFunctions(monitor)) {
			affected.add(c.getEntryPoint());
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
		Writer w = open("conventions.json");
		try {
			w.write("[");
			boolean first = true;
			for (String n : p.getFunctionManager().getCallingConventionNames()) {
				if (!first) {
					w.write(",");
				}
				first = false;
				w.write("\"" + esc(n) + "\"");
			}
			w.write("]");
		}
		finally {
			w.close();
		}
	}

	private static String rootMessage(Throwable t) {
		Throwable c = t;
		while (c.getCause() != null && c.getCause() != c) {
			c = c.getCause();
		}
		String m = c.getMessage();
		if (m == null || m.isEmpty()) {
			m = c.getClass().getSimpleName();
		}
		return m;
	}

	// ------------------------------------------------------------------ i/o

	private List<Op> readOps(File f) throws Exception {
		// A map keyed by address, so two ops on one function collapse to the
		// last one rather than being applied twice.
		Map<String, Op> byAddr = new LinkedHashMap<String, Op>();
		BufferedReader r = new BufferedReader(
			new InputStreamReader(new FileInputStream(f), StandardCharsets.UTF_8));
		try {
			String line;
			while ((line = r.readLine()) != null) {
				line = line.trim();
				if (line.isEmpty() || line.startsWith("#")) {
					continue;
				}
				int tab = line.indexOf('\t');
				if (tab <= 0) {
					continue;
				}
				Op op = new Op();
				op.key = line.substring(0, tab).trim();
				String rest = line.substring(tab + 1);
				int tab2 = rest.indexOf('\t');
				if (tab2 >= 0) {
					op.cc = rest.substring(tab2 + 1).trim();
					rest = rest.substring(0, tab2);
				}
				op.proto = rest.trim();
				if (op.key.isEmpty() || op.proto.isEmpty()) {
					continue;
				}
				byAddr.put(op.key, op);
			}
		}
		finally {
			r.close();
		}
		return new ArrayList<Op>(byAddr.values());
	}

	private void writeResult(File f, List<Op> ops) throws Exception {
		Writer w = new BufferedWriter(
			new OutputStreamWriter(new FileOutputStream(f), StandardCharsets.UTF_8));
		try {
			for (Op op : ops) {
				w.write(tsv(op.key));
				w.write("\t");
				w.write(op.ok ? "ok" : "error");
				w.write("\t");
				w.write(tsv(op.before));
				w.write("\t");
				w.write(tsv(op.message));
				w.write("\n");
			}
		}
		finally {
			w.close();
		}
	}

	// Field separator is TAB and record separator is newline, so neither may
	// survive inside a value. Ghidra type names and parser messages are single
	// line in practice; this is the guard, not an encoding.
	private static String tsv(String s) {
		if (s == null) {
			return "";
		}
		return s.replace('\t', ' ').replace('\r', ' ').replace('\n', ' ');
	}

	// ------------------------------------------------------------ re-export

	// A copy of ExportJSON.writeFunction's shape. It has to stay byte-for-byte
	// compatible with it: the server serves whichever of the two wrote the
	// file last, and clients cannot tell them apart.
	private void exportFunctions(Program p) throws Exception {
		Listing listing = p.getListing();
		Writer w = open("functions.json");
		try {
			w.write("[");
			boolean first = true;
			FunctionIterator it = listing.getFunctions(true);
			while (it.hasNext() && !monitor.isCancelled()) {
				Function f = it.next();
				if (!first) {
					w.write(",");
				}
				first = false;
				writeFunction(w, f);
			}
			w.write("]");
		}
		finally {
			w.close();
		}
	}

	private void writeFunction(Writer w, Function f) throws Exception {
		Address entry = f.getEntryPoint();
		w.write("{");
		field(w, "address", key(entry), true);
		field(w, "address_display", entry.toString(), false);
		field(w, "name", f.getName(), false);
		field(w, "namespace", f.getParentNamespace().getName(true), false);
		field(w, "signature", f.getSignature().getPrototypeString(), false);
		field(w, "calling_convention", f.getCallingConventionName(), false);
		field(w, "return_type", f.getReturnType().getDisplayName(), false);
		num(w, "size", f.getBody().getNumAddresses(), false);
		num(w, "parameter_count", f.getParameterCount(), false);
		bool(w, "is_thunk", f.isThunk(), false);
		bool(w, "is_external", f.isExternal(), false);
		bool(w, "is_inline", f.isInline(), false);
		bool(w, "has_varargs", f.hasVarArgs(), false);
		bool(w, "no_return", f.hasNoReturn(), false);

		StackFrame frame = f.getStackFrame();
		if (frame != null) {
			num(w, "stack_frame_size", frame.getFrameSize(), false);
		}

		w.write(",\"parameters\":[");
		Parameter[] params = f.getParameters();
		for (int i = 0; i < params.length; i++) {
			if (i > 0) {
				w.write(",");
			}
			w.write("{");
			field(w, "name", params[i].getName(), true);
			field(w, "type", params[i].getDataType().getDisplayName(), false);
			num(w, "ordinal", params[i].getOrdinal(), false);
			w.write("}");
		}
		w.write("]");

		writeAddrList(w, "calls", f.getCalledFunctions(monitor));
		writeAddrList(w, "called_by", f.getCallingFunctions(monitor));
		w.write("}");
	}

	private void writeAddrList(Writer w, String name, Set<Function> set) throws Exception {
		w.write(",\"" + name + "\":[");
		boolean first = true;
		for (Function f : set) {
			if (!first) {
				w.write(",");
			}
			first = false;
			w.write("{");
			field(w, "address", key(f.getEntryPoint()), true);
			field(w, "name", f.getName(), false);
			w.write("}");
		}
		w.write("]");
	}

	private void exportDecompiledSubset(Program p, Set<Address> addrs) throws Exception {
		DecompInterface di = new DecompInterface();
		DecompileOptions opts = new DecompileOptions();
		di.setOptions(opts);
		di.toggleCCode(true);
		di.toggleSyntaxTree(true);
		di.setSimplificationStyle("decompile");
		if (!di.openProgram(p)) {
			println("ApplySignature: decompiler unavailable: " + di.getLastMessage());
			return;
		}
		try {
			for (Address a : addrs) {
				if (monitor.isCancelled()) {
					break;
				}
				Function f = p.getListing().getFunctionAt(a);
				if (f == null || f.isExternal()) {
					continue;
				}
				writeDecompiled(di, f);
			}
		}
		finally {
			di.dispose();
		}
	}

	// Same document shape as ExportJSON.exportDecompiled writes per function.
	private void writeDecompiled(DecompInterface di, Function f) throws Exception {
		String k = key(f.getEntryPoint());
		DecompileResults res = di.decompileFunction(f, decompileTimeout, monitor);
		boolean ok = res != null && res.decompileCompleted();
		String c = "";
		String sig = "";
		String err = "";
		String lines = "[]";
		if (ok) {
			DecompiledFunction df = res.getDecompiledFunction();
			if (df != null) {
				c = df.getC();
				sig = df.getSignature();
				lines = lineMap(res);
			}
			else {
				ok = false;
				err = "no decompiled function in results";
			}
		}
		else {
			err = res == null ? "decompiler returned nothing" : res.getErrorMessage();
		}

		Writer fw = open("decompiled/" + fileKey(k) + ".json");
		try {
			fw.write("{");
			field(fw, "address", k, true);
			field(fw, "address_display", f.getEntryPoint().toString(), false);
			field(fw, "name", f.getName(), false);
			field(fw, "signature", sig, false);
			bool(fw, "ok", ok, false);
			field(fw, "error", err, false);
			field(fw, "c", c, false);
			fw.write(",\"lines\":" + lines);
			fw.write("}");
		}
		finally {
			fw.close();
		}
	}

	private String lineMap(DecompileResults res) {
		ClangTokenGroup markup = res == null ? null : res.getCCodeMarkup();
		if (markup == null) {
			return "[]";
		}
		StringBuilder b = new StringBuilder(4096);
		b.append("[");
		boolean firstLine = true;
		for (ClangLine line : DecompilerUtils.toLines(markup)) {
			TreeSet<Address> addrs = new TreeSet<Address>();
			for (ClangToken t : line.getAllTokens()) {
				Address a = t.getMinAddress();
				if (a != null) {
					addrs.add(a);
				}
			}
			if (addrs.isEmpty()) {
				continue;
			}
			if (!firstLine) {
				b.append(",");
			}
			firstLine = false;
			b.append("{\"n\":").append(line.getLineNumber()).append(",\"a\":[");
			boolean firstAddr = true;
			for (Address a : addrs) {
				if (!firstAddr) {
					b.append(",");
				}
				firstAddr = false;
				b.append("\"").append(esc(key(a))).append("\"");
			}
			b.append("]}");
		}
		b.append("]");
		return b.toString();
	}

	// ----------------------------------------------------------- primitives

	// Identical to ExportJSON's, and it has to be: these are the keys the HTTP
	// API resolves paths against.
	private static String key(Address a) {
		if (a == null) {
			return "";
		}
		String s = a.toString().toLowerCase();
		int i = s.lastIndexOf(':');
		String prefix = i >= 0 ? s.substring(0, i + 1) : "";
		String off = i >= 0 ? s.substring(i + 1) : s;
		if (off.startsWith("0x")) {
			off = off.substring(2);
		}
		int z = 0;
		while (z < off.length() - 1 && off.charAt(z) == '0') {
			z++;
		}
		return prefix + off.substring(z);
	}

	private static String fileKey(String k) {
		return k.replace(':', '_').replace('/', '_');
	}

	private Writer open(String rel) throws Exception {
		File f = new File(outDir, rel);
		mkdirs(f.getParentFile());
		return new BufferedWriter(
			new OutputStreamWriter(new FileOutputStream(f), StandardCharsets.UTF_8), 1 << 16);
	}

	private static void mkdirs(File d) throws Exception {
		if (d != null && !d.isDirectory() && !d.mkdirs()) {
			throw new java.io.IOException("cannot create " + d);
		}
	}

	private static void field(Writer w, String name, String value, boolean first) throws Exception {
		if (!first) {
			w.write(",");
		}
		w.write("\"" + name + "\":\"" + esc(value) + "\"");
	}

	private static void num(Writer w, String name, long value, boolean first) throws Exception {
		if (!first) {
			w.write(",");
		}
		w.write("\"" + name + "\":" + value);
	}

	private static void bool(Writer w, String name, boolean value, boolean first) throws Exception {
		if (!first) {
			w.write(",");
		}
		w.write("\"" + name + "\":" + (value ? "true" : "false"));
	}

	private static String esc(String s) {
		if (s == null) {
			return "";
		}
		StringBuilder b = new StringBuilder(s.length() + 16);
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			switch (c) {
				case '"':
					b.append("\\\"");
					break;
				case '\\':
					b.append("\\\\");
					break;
				case '\n':
					b.append("\\n");
					break;
				case '\r':
					b.append("\\r");
					break;
				case '\t':
					b.append("\\t");
					break;
				default:
					if (c < 0x20 || c == 0x7f || Character.isSurrogate(c)) {
						b.append(String.format("\\u%04x", (int) c));
					}
					else {
						b.append(c);
					}
					break;
			}
		}
		return b.toString();
	}
}
