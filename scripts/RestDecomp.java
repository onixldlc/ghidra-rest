// The decompiler: opening it, running one function, and writing the
// decompiled/<addr>.json document.
//
// All three tasks write that document -- the export task for every function,
// the two edit tasks for the handful they invalidated -- and it has to be the
// same shape from each.
//
//@category ghidra-rest
import java.io.Writer;
import java.util.TreeSet;

import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

public final class RestDecomp {

	private RestDecomp() {
	}

	// What one decompiled function turned out to be, for the caller's counters
	// and index entries.
	public static final class Out {
		public boolean ok;
		public int length;
	}

	// Returns null when the decompiler will not start, having said so in the
	// log. Callers decide what an absent decompiler means for them.
	public static DecompInterface open(Ctx c, Program p) {
		DecompInterface di = new DecompInterface();
		DecompileOptions opts = new DecompileOptions();
		di.setOptions(opts);
		di.toggleCCode(true);
		di.toggleSyntaxTree(true);
		di.setSimplificationStyle("decompile");
		if (!di.openProgram(p)) {
			c.log("decompiler unavailable: " + di.getLastMessage());
			return null;
		}
		return di;
	}

	public static Out write(Ctx c, DecompInterface di, Function f, int timeoutSec)
			throws Exception {
		String k = RestAddr.key(f.getEntryPoint());
		DecompileResults res = di.decompileFunction(f, timeoutSec, c.monitor);
		boolean ok = res != null && res.decompileCompleted();
		String code = "";
		String sig = "";
		String err = "";
		String lines = "[]";
		if (ok) {
			DecompiledFunction df = res.getDecompiledFunction();
			if (df != null) {
				code = df.getC();
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

		Writer fw = c.open("decompiled/" + RestAddr.fileKey(k) + ".json");
		try {
			fw.write("{");
			RestJson.field(fw, "address", k, true);
			RestJson.field(fw, "address_display", f.getEntryPoint().toString(), false);
			RestJson.field(fw, "name", f.getName(), false);
			RestJson.field(fw, "signature", sig, false);
			RestJson.bool(fw, "ok", ok, false);
			RestJson.field(fw, "error", err, false);
			RestJson.field(fw, "c", code, false);
			fw.write(",\"lines\":" + lines);
			fw.write("}");
		}
		finally {
			fw.close();
		}

		Out out = new Out();
		out.ok = ok;
		out.length = code.length();
		return out;
	}

	// Decompiles a set of functions and writes each one's document. Used by
	// the edit tasks, which know exactly which functions they invalidated.
	public static int writeSubset(Ctx c, Program p, java.util.Set<Address> addrs, int timeoutSec)
			throws Exception {
		if (addrs.isEmpty()) {
			return 0;
		}
		DecompInterface di = open(c, p);
		if (di == null) {
			return 0;
		}
		int n = 0;
		try {
			for (Address a : addrs) {
				if (c.cancelled()) {
					break;
				}
				Function f = p.getListing().getFunctionAt(a);
				if (f == null || f.isExternal()) {
					continue;
				}
				write(c, di, f, timeoutSec);
				n++;
			}
		}
		finally {
			di.dispose();
		}
		return n;
	}

	// Which instructions produced each line of C. Ghidra keeps this on the
	// markup tree -- every ClangToken remembers the address it came from -- and
	// it is what the Decompiler window uses to highlight the matching
	// instructions in the Listing. getC() throws it away, so read it off the
	// markup instead and ship it alongside the text. Lines that are pure
	// punctuation map to nothing and are left out.
	public static String lineMap(DecompileResults res) {
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
				b.append(RestJson.quoted(RestAddr.key(a)));
			}
			b.append("]}");
		}
		b.append("]");
		return b.toString();
	}
}
