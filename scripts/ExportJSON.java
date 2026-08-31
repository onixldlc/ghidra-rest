// Exports one analyzed program to the flat JSON artifact set that ghidrarest
// serves over HTTP. Run by analyzeHeadless as a -postScript.
//
// Usage:
//   -postScript ExportJSON.java <outdir> [decompile] [maxDecompileFuncs]
//                               [decompileTimeoutSec] [maxExportBytes]
//
// Everything the REST API answers comes out of this one pass. There is no
// long-lived Ghidra process behind the server: analysis happens once, writes
// files, and exits. That is the whole design -- a request never blocks on the
// decompiler, and a crashed job cannot take the server with it.
//
// Artifacts written under <outdir>:
//   summary.json          program metadata and counts
//   functions.json        every function, with call edges
//   strings.json          defined string data
//   symbols.json          symbol table (non-dynamic)
//   imports.json          external locations, grouped per library on read
//   exports.json          external entry points
//   xrefs.json            {address: {to: [...], from: [...]}}
//   types.json            composites, enums, typedefs, function definitions
//   memory/index.json     blocks, plus raw bytes of initialised ones
//   disasm/<addr>.json      one instruction listing per function
//   disasm/index.json       instruction counts per function
//   decompiled/<addr>.json  one C listing per function
//   decompiled/index.json   which functions got decompiled, and why not
//
//@category ghidra-rest

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.TreeSet;

import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.StackFrame;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalLocationIterator;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

public class ExportJSON extends GhidraScript {

	// Caps. Overridable per job from the server, defaults chosen so a hostile
	// or merely enormous binary cannot fill the disk.
	private boolean decompile = true;
	private int maxDecompileFuncs = 20000;
	private int decompileTimeout = 60;
	private long maxExportBytes = 256L * 1024 * 1024;
	private int maxSymbols = 400000;
	// per function; a runaway body should not write a gigabyte of JSON
	private int maxDisasmInstructions = 200000;

	private File outDir;

	private int countFunctions;
	private int countStrings;
	private int countSymbols;
	private int countImports;
	private int countExports;
	private int countTypes;
	private int countXrefs;
	private long countInstructions;
	private int countLocalFunctions;
	private int countDecompiled;
	private int countDecompileFailed;
	private long bytesExported;

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 1) {
			throw new IllegalArgumentException(
				"usage: ExportJSON <outdir> [decompile] [maxFuncs] [timeoutSec] [maxExportBytes]");
		}
		outDir = new File(args[0]);
		if (args.length > 1) {
			decompile = !"false".equalsIgnoreCase(args[1]) && !"0".equals(args[1]);
		}
		if (args.length > 2) {
			maxDecompileFuncs = Integer.parseInt(args[2]);
		}
		if (args.length > 3) {
			decompileTimeout = Integer.parseInt(args[3]);
		}
		if (args.length > 4) {
			maxExportBytes = Long.parseLong(args[4]);
		}

		mkdirs(outDir);

		Program p = currentProgram;
		println("ExportJSON: program=" + p.getName() + " out=" + outDir.getAbsolutePath());

		// Order matters only in that summary.json is written last: the server
		// treats its presence as "this job produced a complete artifact set".
		exportFunctions(p);
		exportStrings(p);
		exportSymbols(p);
		exportImports(p);
		exportExports(p);
		exportTypes(p);
		exportXrefs(p);
		exportMemory(p);
		exportDisasm(p);
		if (decompile) {
			exportDecompiled(p);
		}
		else {
			mkdirs(new File(outDir, "decompiled"));
			Writer w = open("decompiled/index.json");
			w.write("[]");
			w.close();
		}
		exportSummary(p);

		println("ExportJSON: done functions=" + countFunctions + " decompiled=" + countDecompiled +
			" strings=" + countStrings + " symbols=" + countSymbols);
	}

	// Progress markers. Nothing reads these but a human and guttex's loading
	// screen, so they are plain and prefixed: one grep, no format to parse.
	private void stage(String name) {
		println("ExportJSON: stage " + name);
	}

	// ---------------------------------------------------------------- funcs

	private void exportFunctions(Program p) throws Exception {
		stage("functions");
		Listing listing = p.getListing();
		Writer w = open("functions.json");
		w.write("[");
		boolean first = true;
		FunctionIterator it = listing.getFunctions(true);
		while (it.hasNext() && !monitor.isCancelled()) {
			Function f = it.next();
			if (!first) {
				w.write(",");
			}
			first = false;
			countFunctions++;
			if (!f.isExternal()) {
				countLocalFunctions++;
			}
			writeFunction(w, f);
			if (countFunctions % 500 == 0) {
				println("ExportJSON: functions " + countFunctions);
			}
		}
		w.write("]");
		w.close();
		// The periodic line counts in 500s, so it is a floor. This is the total.
		println("ExportJSON: functions total=" + countFunctions);
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

	private void writeAddrList(Writer w, String name, java.util.Set<Function> set) throws Exception {
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

	// -------------------------------------------------------------- strings

	private void exportStrings(Program p) throws Exception {
		stage("strings");
		ReferenceManager rm = p.getReferenceManager();
		Writer w = open("strings.json");
		w.write("[");
		boolean first = true;
		DataIterator it = p.getListing().getDefinedData(true);
		while (it.hasNext() && !monitor.isCancelled()) {
			Data d = it.next();
			if (!d.hasStringValue()) {
				continue;
			}
			Object v = d.getValue();
			if (v == null) {
				continue;
			}
			if (!first) {
				w.write(",");
			}
			first = false;
			countStrings++;
			w.write("{");
			field(w, "address", key(d.getAddress()), true);
			field(w, "address_display", d.getAddress().toString(), false);
			field(w, "value", v.toString(), false);
			field(w, "type", d.getDataType().getName(), false);
			num(w, "length", d.getLength(), false);
			num(w, "reference_count", rm.getReferenceCountTo(d.getAddress()), false);
			w.write("}");
		}
		w.write("]");
		w.close();
	}

	// -------------------------------------------------------------- symbols

	private void exportSymbols(Program p) throws Exception {
		stage("symbols");
		SymbolTable st = p.getSymbolTable();
		Writer w = open("symbols.json");
		w.write("[");
		boolean first = true;
		SymbolIterator it = st.getAllSymbols(false);
		while (it.hasNext() && !monitor.isCancelled() && countSymbols < maxSymbols) {
			Symbol s = it.next();
			if (!first) {
				w.write(",");
			}
			first = false;
			countSymbols++;
			w.write("{");
			field(w, "address", key(s.getAddress()), true);
			field(w, "address_display", s.getAddress().toString(), false);
			field(w, "name", s.getName(), false);
			field(w, "full_name", s.getName(true), false);
			field(w, "type", s.getSymbolType().toString(), false);
			field(w, "source", s.getSource().toString(), false);
			field(w, "namespace", s.getParentNamespace().getName(true), false);
			bool(w, "primary", s.isPrimary(), false);
			bool(w, "global", s.isGlobal(), false);
			bool(w, "external", s.isExternal(), false);
			num(w, "reference_count", s.getReferenceCount(), false);
			w.write("}");
		}
		w.write("]");
		w.close();
	}

	// -------------------------------------------------------------- imports

	private void exportImports(Program p) throws Exception {
		stage("imports");
		ExternalManager em = p.getExternalManager();
		Writer w = open("imports.json");
		w.write("[");
		boolean first = true;
		String[] libs = em.getExternalLibraryNames();
		for (String lib : libs) {
			ExternalLocationIterator it = em.getExternalLocations(lib);
			while (it.hasNext() && !monitor.isCancelled()) {
				ExternalLocation loc = it.next();
				if (!first) {
					w.write(",");
				}
				first = false;
				countImports++;
				w.write("{");
				field(w, "library", lib, true);
				field(w, "name", loc.getLabel(), false);
				field(w, "original_name", loc.getOriginalImportedName(), false);
				bool(w, "is_function", loc.isFunction(), false);
				Address a = loc.getAddress();
				field(w, "address", a == null ? "" : key(a), false);
				Symbol s = loc.getSymbol();
				if (s != null) {
					field(w, "thunk_address", key(s.getAddress()), false);
				}
				w.write("}");
			}
		}
		w.write("]");
		w.close();
	}

	// -------------------------------------------------------------- exports

	private void exportExports(Program p) throws Exception {
		stage("exports");
		SymbolTable st = p.getSymbolTable();
		Writer w = open("exports.json");
		w.write("[");
		boolean first = true;
		AddressIterator it = st.getExternalEntryPointIterator();
		while (it.hasNext() && !monitor.isCancelled()) {
			Address a = it.next();
			Symbol s = st.getPrimarySymbol(a);
			if (!first) {
				w.write(",");
			}
			first = false;
			countExports++;
			w.write("{");
			field(w, "address", key(a), true);
			field(w, "address_display", a.toString(), false);
			field(w, "name", s == null ? "" : s.getName(), false);
			bool(w, "is_function", p.getFunctionManager().getFunctionAt(a) != null, false);
			w.write("}");
		}
		w.write("]");
		w.close();
	}

	// ---------------------------------------------------------------- types

	private void exportTypes(Program p) throws Exception {
		stage("types");
		DataTypeManager dtm = p.getDataTypeManager();
		Writer w = open("types.json");
		w.write("[");
		boolean first = true;
		Iterator<DataType> it = dtm.getAllDataTypes();
		while (it.hasNext() && !monitor.isCancelled()) {
			DataType dt = it.next();
			String kind = kindOf(dt);
			if (kind == null) {
				// Pointers, arrays and builtins are derivable from the types
				// that reference them; listing them buries the interesting ones.
				continue;
			}
			if (!first) {
				w.write(",");
			}
			first = false;
			countTypes++;
			w.write("{");
			field(w, "name", dt.getName(), true);
			field(w, "path", dt.getPathName(), false);
			field(w, "kind", kind, false);
			num(w, "size", dt.isZeroLength() ? 0 : dt.getLength(), false);
			if (dt instanceof Composite) {
				Composite c = (Composite) dt;
				w.write(",\"members\":[");
				DataTypeComponent[] comps = c.getDefinedComponents();
				for (int i = 0; i < comps.length; i++) {
					if (i > 0) {
						w.write(",");
					}
					w.write("{");
					field(w, "name", comps[i].getFieldName(), true);
					field(w, "type", comps[i].getDataType().getDisplayName(), false);
					num(w, "offset", comps[i].getOffset(), false);
					num(w, "length", comps[i].getLength(), false);
					field(w, "comment", comps[i].getComment(), false);
					w.write("}");
				}
				w.write("]");
			}
			else if (dt instanceof ghidra.program.model.data.Enum) {
				ghidra.program.model.data.Enum e = (ghidra.program.model.data.Enum) dt;
				w.write(",\"values\":[");
				String[] names = e.getNames();
				for (int i = 0; i < names.length; i++) {
					if (i > 0) {
						w.write(",");
					}
					w.write("{");
					field(w, "name", names[i], true);
					num(w, "value", e.getValue(names[i]), false);
					w.write("}");
				}
				w.write("]");
			}
			else if (dt instanceof TypeDef) {
				field(w, "base_type", ((TypeDef) dt).getBaseDataType().getDisplayName(), false);
			}
			else if (dt instanceof FunctionDefinition) {
				field(w, "prototype", ((FunctionDefinition) dt).getPrototypeString(), false);
			}
			w.write("}");
		}
		w.write("]");
		w.close();
	}

	private String kindOf(DataType dt) {
		if (dt instanceof ghidra.program.model.data.Structure) {
			return "struct";
		}
		if (dt instanceof ghidra.program.model.data.Union) {
			return "union";
		}
		if (dt instanceof ghidra.program.model.data.Enum) {
			return "enum";
		}
		if (dt instanceof FunctionDefinition) {
			return "function_definition";
		}
		if (dt instanceof TypeDef) {
			return "typedef";
		}
		return null;
	}

	// ---------------------------------------------------------------- xrefs

	private void exportXrefs(Program p) throws Exception {
		stage("xrefs");
		ReferenceManager rm = p.getReferenceManager();
		Writer w = open("xrefs.json");
		w.write("{");
		boolean first = true;

		// Only function entries and defined data get an entry. Every address in
		// the program would be both enormous and mostly empty.
		FunctionIterator fit = p.getListing().getFunctions(true);
		while (fit.hasNext() && !monitor.isCancelled()) {
			Address a = fit.next().getEntryPoint();
			first = writeXrefEntry(w, rm, a, first);
		}
		DataIterator dit = p.getListing().getDefinedData(true);
		while (dit.hasNext() && !monitor.isCancelled()) {
			Data d = dit.next();
			if (rm.getReferenceCountTo(d.getAddress()) == 0) {
				continue;
			}
			first = writeXrefEntry(w, rm, d.getAddress(), first);
		}
		w.write("}");
		w.close();
	}

	private boolean writeXrefEntry(Writer w, ReferenceManager rm, Address a, boolean first)
			throws Exception {
		if (!first) {
			w.write(",");
		}
		countXrefs++;
		w.write("\"" + esc(key(a)) + "\":{\"to\":[");
		ReferenceIterator to = rm.getReferencesTo(a);
		boolean f2 = true;
		while (to.hasNext()) {
			Reference r = to.next();
			if (!f2) {
				w.write(",");
			}
			f2 = false;
			writeRef(w, r, r.getFromAddress());
		}
		w.write("],\"from\":[");
		Reference[] from = rm.getReferencesFrom(a);
		for (int i = 0; i < from.length; i++) {
			if (i > 0) {
				w.write(",");
			}
			writeRef(w, from[i], from[i].getToAddress());
		}
		w.write("]}");
		return false;
	}

	private void writeRef(Writer w, Reference r, Address other) throws Exception {
		w.write("{");
		field(w, "address", key(other), true);
		field(w, "address_display", other.toString(), false);
		field(w, "type", r.getReferenceType().getName(), false);
		bool(w, "is_call", r.getReferenceType().isCall(), false);
		bool(w, "is_jump", r.getReferenceType().isJump(), false);
		bool(w, "is_data", r.getReferenceType().isData(), false);
		field(w, "source", r.getSource().toString(), false);
		Function fn = getFunctionContaining(other);
		if (fn != null) {
			field(w, "function", fn.getName(), false);
			field(w, "function_address", key(fn.getEntryPoint()), false);
		}
		w.write("}");
	}

	// --------------------------------------------------------------- memory

	private void exportMemory(Program p) throws Exception {
		stage("memory");
		File memDir = new File(outDir, "memory");
		mkdirs(memDir);
		Memory mem = p.getMemory();
		Writer w = open("memory/index.json");
		w.write("[");
		MemoryBlock[] blocks = mem.getBlocks();
		for (int i = 0; i < blocks.length; i++) {
			MemoryBlock b = blocks[i];
			if (i > 0) {
				w.write(",");
			}
			String file = "";
			long written = 0;
			if (b.isInitialized() && bytesExported < maxExportBytes) {
				file = "block-" + i + ".bin";
				written = dumpBlock(b, new File(memDir, file));
				bytesExported += written;
			}
			w.write("{");
			field(w, "name", b.getName(), true);
			field(w, "start", key(b.getStart()), false);
			field(w, "start_display", b.getStart().toString(), false);
			field(w, "end", key(b.getEnd()), false);
			num(w, "size", b.getSize(), false);
			bool(w, "read", b.isRead(), false);
			bool(w, "write", b.isWrite(), false);
			bool(w, "execute", b.isExecute(), false);
			bool(w, "volatile", b.isVolatile(), false);
			bool(w, "initialized", b.isInitialized(), false);
			bool(w, "overlay", b.isOverlay(), false);
			field(w, "type", b.getType().toString(), false);
			field(w, "source", b.getSourceName(), false);
			field(w, "file", file, false);
			num(w, "bytes_exported", written, false);
			w.write("}");
		}
		w.write("]");
		w.close();
	}

	private long dumpBlock(MemoryBlock b, File dest) throws Exception {
		long budget = maxExportBytes - bytesExported;
		if (budget <= 0) {
			return 0;
		}
		long total = 0;
		InputStream in = b.getData();
		OutputStream out = new FileOutputStream(dest);
		try {
			byte[] buf = new byte[64 * 1024];
			while (total < budget) {
				int want = (int) Math.min(buf.length, budget - total);
				int n = in.read(buf, 0, want);
				if (n < 0) {
					break;
				}
				out.write(buf, 0, n);
				total += n;
			}
		}
		finally {
			out.close();
			in.close();
		}
		return total;
	}

	// ----------------------------------------------------------- decompiled

	private void exportDecompiled(Program p) throws Exception {
		stage("decompiled");
		File dir = new File(outDir, "decompiled");
		mkdirs(dir);

		DecompInterface di = new DecompInterface();
		DecompileOptions opts = new DecompileOptions();
		di.setOptions(opts);
		di.toggleCCode(true);
		di.toggleSyntaxTree(true);
		di.setSimplificationStyle("decompile");
		if (!di.openProgram(p)) {
			println("ExportJSON: decompiler unavailable: " + di.getLastMessage());
			Writer idx = open("decompiled/index.json");
			idx.write("[]");
			idx.close();
			return;
		}

		Writer idx = open("decompiled/index.json");
		idx.write("[");
		boolean first = true;
		int seen = 0;
		// Externals are skipped below and the cap stops the walk early, so the
		// number worth reporting is neither the function count nor the cap.
		println("ExportJSON: decompiling 0/" + Math.min(countLocalFunctions, maxDecompileFuncs));
		try {
			FunctionIterator it = p.getListing().getFunctions(true);
			while (it.hasNext() && !monitor.isCancelled()) {
				Function f = it.next();
				if (f.isExternal()) {
					continue;
				}
				seen++;
				if (seen > maxDecompileFuncs) {
					println("ExportJSON: decompile cap " + maxDecompileFuncs + " reached");
					break;
				}
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
				fw.close();

				if (ok) {
					countDecompiled++;
				}
				else {
					countDecompileFailed++;
				}

				if (!first) {
					idx.write(",");
				}
				first = false;
				idx.write("{");
				field(idx, "address", k, true);
				field(idx, "name", f.getName(), false);
				bool(idx, "ok", ok, false);
				num(idx, "length", c.length(), false);
				idx.write("}");

				if (seen % 200 == 0) {
					println("ExportJSON: decompiled " + countDecompiled + "/" + seen);
				}
			}
		}
		finally {
			di.dispose();
			idx.write("]");
			idx.close();
		}
	}

	// Which instructions produced each line of C. Ghidra keeps this on the
	// markup tree -- every ClangToken remembers the address it came from -- and
	// it is what the Decompiler window uses to highlight the matching
	// instructions in the Listing. getC() throws it away, so read it off the
	// markup instead and ship it alongside the text. Lines that are pure
	// punctuation map to nothing and are left out.
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

	// -------------------------------------------------------------- disasm

	// One instruction listing per function, laid out like the decompiled set:
	// disasm/<addr>.json plus an index. Nearly free next to decompilation --
	// the instructions are already in the listing, this only serialises them.
	private void exportDisasm(Program p) throws Exception {
		stage("disasm");
		mkdirs(new File(outDir, "disasm"));
		Listing listing = p.getListing();

		Writer idx = open("disasm/index.json");
		idx.write("[");
		boolean firstFn = true;
		try {
			FunctionIterator it = listing.getFunctions(true);
			while (it.hasNext() && !monitor.isCancelled()) {
				Function f = it.next();
				if (f.isExternal()) {
					// no body to disassemble; the thunk that calls it has one
					continue;
				}
				String k = key(f.getEntryPoint());
				AddressSetView body = f.getBody();

				Writer fw = open("disasm/" + fileKey(k) + ".json");
				fw.write("{");
				field(fw, "address", k, true);
				field(fw, "address_display", f.getEntryPoint().toString(), false);
				field(fw, "name", f.getName(), false);
				fw.write(",\"instructions\":[");
				int n = 0;
				try {
					InstructionIterator iit = listing.getInstructions(body, true);
					while (iit.hasNext() && !monitor.isCancelled() && n < maxDisasmInstructions) {
						Instruction ins = iit.next();
						if (n > 0) {
							fw.write(",");
						}
						fw.write("{");
						field(fw, "address", key(ins.getAddress()), true);
						field(fw, "address_display", ins.getAddress().toString(), false);
						field(fw, "bytes", hexBytes(ins), false);
						field(fw, "mnemonic", ins.getMnemonicString(), false);
						field(fw, "operands", operandText(ins), false);
						field(fw, "text", ins.toString(), false);
						field(fw, "comment", commentText(listing, ins), false);
						num(fw, "length", ins.getLength(), false);
						bool(fw, "is_call", ins.getFlowType().isCall(), false);
						bool(fw, "is_jump", ins.getFlowType().isJump(), false);
						bool(fw, "is_terminal", ins.getFlowType().isTerminal(), false);
						field(fw, "flow", flowTarget(ins), false);
						fw.write("}");
						n++;
						countInstructions++;
					}
				}
				finally {
					fw.write("]");
					num(fw, "count", n, false);
					bool(fw, "truncated", n >= maxDisasmInstructions, false);
					fw.write("}");
					fw.close();
				}

				if (!firstFn) {
					idx.write(",");
				}
				firstFn = false;
				idx.write("{");
				field(idx, "address", k, true);
				field(idx, "name", f.getName(), false);
				num(idx, "count", n, false);
				idx.write("}");
			}
		}
		finally {
			idx.write("]");
			idx.close();
		}
	}

	private static String hexBytes(Instruction ins) {
		try {
			byte[] b = ins.getBytes();
			StringBuilder sb = new StringBuilder(b.length * 2);
			for (int i = 0; i < b.length; i++) {
				sb.append(String.format("%02x", b[i] & 0xff));
			}
			return sb.toString();
		}
		catch (Exception e) {
			return "";
		}
	}

	// Ghidra renders each operand separately; the joined form is what a listing
	// window shows to the right of the mnemonic.
	private static String operandText(Instruction ins) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < ins.getNumOperands(); i++) {
			if (i > 0) {
				sb.append(",");
			}
			sb.append(ins.getDefaultOperandRepresentation(i));
		}
		return sb.toString();
	}

	private static String commentText(Listing listing, Instruction ins) {
		String c = listing.getComment(CodeUnit.EOL_COMMENT, ins.getAddress());
		if (c == null) {
			c = listing.getComment(CodeUnit.PRE_COMMENT, ins.getAddress());
		}
		return c == null ? "" : c;
	}

	// Where a call or jump goes, when the target is a single known address.
	private static String flowTarget(Instruction ins) {
		Address[] flows = ins.getFlows();
		if (flows == null || flows.length != 1) {
			return "";
		}
		return key(flows[0]);
	}

	// -------------------------------------------------------------- summary

	private void exportSummary(Program p) throws Exception {
		stage("summary");
		Writer w = open("summary.json");
		w.write("{");
		field(w, "name", p.getName(), true);
		field(w, "executable_path", p.getExecutablePath(), false);
		field(w, "executable_format", p.getExecutableFormat(), false);
		field(w, "md5", p.getExecutableMD5(), false);
		field(w, "sha256", p.getExecutableSHA256(), false);
		field(w, "language", p.getLanguageID().getIdAsString(), false);
		field(w, "processor", p.getLanguage().getProcessor().toString(), false);
		field(w, "endian", p.getLanguage().isBigEndian() ? "big" : "little", false);
		num(w, "address_size", p.getDefaultPointerSize() * 8, false);
		field(w, "compiler_spec", p.getCompilerSpec().getCompilerSpecID().getIdAsString(), false);
		field(w, "image_base", key(p.getImageBase()), false);
		field(w, "min_address", key(p.getMinAddress()), false);
		field(w, "max_address", key(p.getMaxAddress()), false);
		field(w, "creation_date", String.valueOf(p.getCreationDate()), false);
		field(w, "ghidra_version", Application.getApplicationVersion(), false);
		num(w, "memory_bytes_exported", bytesExported, false);

		w.write(",\"counts\":{");
		w.write("\"functions\":" + countFunctions);
		w.write(",\"strings\":" + countStrings);
		w.write(",\"symbols\":" + countSymbols);
		w.write(",\"imports\":" + countImports);
		w.write(",\"exports\":" + countExports);
		w.write(",\"types\":" + countTypes);
		w.write(",\"xref_entries\":" + countXrefs);
		w.write(",\"instructions\":" + countInstructions);
		w.write(",\"decompiled\":" + countDecompiled);
		w.write(",\"decompile_failed\":" + countDecompileFailed);
		w.write("}");

		// The calling conventions this program's compiler spec defines. Only
		// these names are accepted when a signature is edited later, and there is
		// no way to ask for them without a Ghidra process, so they ship here.
		w.write(",\"calling_conventions\":[");
		boolean firstCC = true;
		for (String cc : p.getFunctionManager().getCallingConventionNames()) {
			if (!firstCC) {
				w.write(",");
			}
			firstCC = false;
			w.write("\"" + esc(cc) + "\"");
		}
		w.write("]");

		w.write(",\"entry_points\":[");
		List<String> eps = new ArrayList<String>();
		AddressIterator it = p.getSymbolTable().getExternalEntryPointIterator();
		while (it.hasNext() && eps.size() < 64) {
			eps.add(key(it.next()));
		}
		for (int i = 0; i < eps.size(); i++) {
			if (i > 0) {
				w.write(",");
			}
			w.write("\"" + esc(eps.get(i)) + "\"");
		}
		w.write("]");

		w.write("}");
		w.close();
	}

	// ----------------------------------------------------------- primitives

	// key normalises an address to the form the HTTP API uses in paths:
	// lower case, no 0x, no leading zeros, address space prefix kept when the
	// program has more than the default space. The Go side does the same to
	// whatever a client sends, so 0x00401000, 401000 and 00401000 all hit.
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

	// Address keys can carry a space prefix with a colon in it, which is not a
	// portable filename character.
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
					// Control characters and lone surrogates would make the
					// output invalid JSON; decompiled C and raw strings from a
					// binary contain both.
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
