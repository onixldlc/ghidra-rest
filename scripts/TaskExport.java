// Exports one analyzed program to the flat JSON artifact set that ghidrarest
// serves over HTTP.
//
//   RestScript.java export <outdir> [decompile] [maxDecompileFuncs]
//                          [decompileTimeoutSec] [maxExportBytes]
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
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
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

import ghidra.app.decompiler.DecompInterface;

public class TaskExport implements Task {

	@Override
	public String name() {
		return "export";
	}

	@Override
	public String usage() {
		return "<outdir> [decompile] [maxFuncs] [timeoutSec] [maxExportBytes]";
	}

	@Override
	public String logTag() {
		// guttex matches on this exact string. See Task.logTag.
		return "ExportJSON";
	}

	// Caps. Overridable per job from the server, defaults chosen so a hostile
	// or merely enormous binary cannot fill the disk.
	private boolean decompile = true;
	private int maxDecompileFuncs = 20000;
	private int decompileTimeout = 60;
	private long maxExportBytes = 256L * 1024 * 1024;
	private int maxSymbols = 400000;
	// per function; a runaway body should not write a gigabyte of JSON
	private int maxDisasmInstructions = 200000;

	private Ctx c;

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
	public void run(Ctx ctx, String[] args) throws Exception {
		this.c = ctx;
		if (args.length > 0) {
			decompile = !"false".equalsIgnoreCase(args[0]) && !"0".equals(args[0]);
		}
		if (args.length > 1) {
			maxDecompileFuncs = Integer.parseInt(args[1]);
		}
		if (args.length > 2) {
			decompileTimeout = Integer.parseInt(args[2]);
		}
		if (args.length > 3) {
			maxExportBytes = Long.parseLong(args[3]);
		}

		Program p = c.program;
		c.log("program=" + p.getName() + " out=" + c.outDir.getAbsolutePath());

		// Order matters only in that summary.json is written last: the server
		// treats its presence as "this job produced a complete artifact set".
		c.stage("functions");
		int[] counts = RestFunc.exportAll(c, p, true);
		countFunctions = counts[0];
		countLocalFunctions = counts[1];

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
			c.dir("decompiled");
			Writer w = c.open("decompiled/index.json");
			w.write("[]");
			w.close();
		}
		exportSummary(p);

		c.log("done functions=" + countFunctions + " decompiled=" + countDecompiled +
			" strings=" + countStrings + " symbols=" + countSymbols);
	}

	// -------------------------------------------------------------- strings

	private void exportStrings(Program p) throws Exception {
		c.stage("strings");
		ReferenceManager rm = p.getReferenceManager();
		Writer w = c.open("strings.json");
		w.write("[");
		boolean first = true;
		DataIterator it = p.getListing().getDefinedData(true);
		while (it.hasNext() && !c.cancelled()) {
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
			RestJson.field(w, "address", RestAddr.key(d.getAddress()), true);
			RestJson.field(w, "address_display", d.getAddress().toString(), false);
			RestJson.field(w, "value", v.toString(), false);
			RestJson.field(w, "type", d.getDataType().getName(), false);
			RestJson.num(w, "length", d.getLength(), false);
			RestJson.num(w, "reference_count", rm.getReferenceCountTo(d.getAddress()), false);
			w.write("}");
		}
		w.write("]");
		w.close();
	}

	// -------------------------------------------------------------- symbols

	private void exportSymbols(Program p) throws Exception {
		c.stage("symbols");
		SymbolTable st = p.getSymbolTable();
		Writer w = c.open("symbols.json");
		w.write("[");
		boolean first = true;
		SymbolIterator it = st.getAllSymbols(false);
		while (it.hasNext() && !c.cancelled() && countSymbols < maxSymbols) {
			Symbol s = it.next();
			if (!first) {
				w.write(",");
			}
			first = false;
			countSymbols++;
			w.write("{");
			RestJson.field(w, "address", RestAddr.key(s.getAddress()), true);
			RestJson.field(w, "address_display", s.getAddress().toString(), false);
			RestJson.field(w, "name", s.getName(), false);
			RestJson.field(w, "full_name", s.getName(true), false);
			RestJson.field(w, "type", s.getSymbolType().toString(), false);
			RestJson.field(w, "source", s.getSource().toString(), false);
			RestJson.field(w, "namespace", s.getParentNamespace().getName(true), false);
			RestJson.bool(w, "primary", s.isPrimary(), false);
			RestJson.bool(w, "global", s.isGlobal(), false);
			RestJson.bool(w, "external", s.isExternal(), false);
			RestJson.num(w, "reference_count", s.getReferenceCount(), false);
			w.write("}");
		}
		w.write("]");
		w.close();
	}

	// -------------------------------------------------------------- imports

	private void exportImports(Program p) throws Exception {
		c.stage("imports");
		ExternalManager em = p.getExternalManager();
		Writer w = c.open("imports.json");
		w.write("[");
		boolean first = true;
		String[] libs = em.getExternalLibraryNames();
		for (String lib : libs) {
			ExternalLocationIterator it = em.getExternalLocations(lib);
			while (it.hasNext() && !c.cancelled()) {
				ExternalLocation loc = it.next();
				if (!first) {
					w.write(",");
				}
				first = false;
				countImports++;
				w.write("{");
				RestJson.field(w, "library", lib, true);
				RestJson.field(w, "name", loc.getLabel(), false);
				RestJson.field(w, "original_name", loc.getOriginalImportedName(), false);
				RestJson.bool(w, "is_function", loc.isFunction(), false);
				Address a = loc.getAddress();
				RestJson.field(w, "address", a == null ? "" : RestAddr.key(a), false);
				Symbol s = loc.getSymbol();
				if (s != null) {
					RestJson.field(w, "thunk_address", RestAddr.key(s.getAddress()), false);
				}
				w.write("}");
			}
		}
		w.write("]");
		w.close();
	}

	// -------------------------------------------------------------- exports

	private void exportExports(Program p) throws Exception {
		c.stage("exports");
		SymbolTable st = p.getSymbolTable();
		Writer w = c.open("exports.json");
		w.write("[");
		boolean first = true;
		AddressIterator it = st.getExternalEntryPointIterator();
		while (it.hasNext() && !c.cancelled()) {
			Address a = it.next();
			Symbol s = st.getPrimarySymbol(a);
			if (!first) {
				w.write(",");
			}
			first = false;
			countExports++;
			w.write("{");
			RestJson.field(w, "address", RestAddr.key(a), true);
			RestJson.field(w, "address_display", a.toString(), false);
			RestJson.field(w, "name", s == null ? "" : s.getName(), false);
			RestJson.bool(w, "is_function", p.getFunctionManager().getFunctionAt(a) != null, false);
			w.write("}");
		}
		w.write("]");
		w.close();
	}

	// ---------------------------------------------------------------- types

	private void exportTypes(Program p) throws Exception {
		c.stage("types");
		DataTypeManager dtm = p.getDataTypeManager();
		Writer w = c.open("types.json");
		w.write("[");
		boolean first = true;
		Iterator<DataType> it = dtm.getAllDataTypes();
		while (it.hasNext() && !c.cancelled()) {
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
			RestJson.field(w, "name", dt.getName(), true);
			RestJson.field(w, "path", dt.getPathName(), false);
			RestJson.field(w, "kind", kind, false);
			RestJson.num(w, "size", dt.isZeroLength() ? 0 : dt.getLength(), false);
			if (dt instanceof Composite) {
				Composite comp = (Composite) dt;
				w.write(",\"members\":[");
				DataTypeComponent[] comps = comp.getDefinedComponents();
				for (int i = 0; i < comps.length; i++) {
					if (i > 0) {
						w.write(",");
					}
					w.write("{");
					RestJson.field(w, "name", comps[i].getFieldName(), true);
					RestJson.field(w, "type", comps[i].getDataType().getDisplayName(), false);
					RestJson.num(w, "offset", comps[i].getOffset(), false);
					RestJson.num(w, "length", comps[i].getLength(), false);
					RestJson.field(w, "comment", comps[i].getComment(), false);
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
					RestJson.field(w, "name", names[i], true);
					RestJson.num(w, "value", e.getValue(names[i]), false);
					w.write("}");
				}
				w.write("]");
			}
			else if (dt instanceof TypeDef) {
				RestJson.field(w, "base_type", ((TypeDef) dt).getBaseDataType().getDisplayName(),
					false);
			}
			else if (dt instanceof FunctionDefinition) {
				RestJson.field(w, "prototype", ((FunctionDefinition) dt).getPrototypeString(),
					false);
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
		c.stage("xrefs");
		ReferenceManager rm = p.getReferenceManager();
		Writer w = c.open("xrefs.json");
		w.write("{");
		boolean first = true;

		// Only function entries and defined data get an entry. Every address in
		// the program would be both enormous and mostly empty.
		FunctionIterator fit = p.getListing().getFunctions(true);
		while (fit.hasNext() && !c.cancelled()) {
			Address a = fit.next().getEntryPoint();
			first = writeXrefEntry(p, w, rm, a, first);
		}
		DataIterator dit = p.getListing().getDefinedData(true);
		while (dit.hasNext() && !c.cancelled()) {
			Data d = dit.next();
			if (rm.getReferenceCountTo(d.getAddress()) == 0) {
				continue;
			}
			first = writeXrefEntry(p, w, rm, d.getAddress(), first);
		}
		w.write("}");
		w.close();
	}

	private boolean writeXrefEntry(Program p, Writer w, ReferenceManager rm, Address a,
			boolean first) throws Exception {
		if (!first) {
			w.write(",");
		}
		countXrefs++;
		w.write(RestJson.quoted(RestAddr.key(a)) + ":{\"to\":[");
		ReferenceIterator to = rm.getReferencesTo(a);
		boolean f2 = true;
		while (to.hasNext()) {
			Reference r = to.next();
			if (!f2) {
				w.write(",");
			}
			f2 = false;
			writeRef(p, w, r, r.getFromAddress());
		}
		w.write("],\"from\":[");
		Reference[] from = rm.getReferencesFrom(a);
		for (int i = 0; i < from.length; i++) {
			if (i > 0) {
				w.write(",");
			}
			writeRef(p, w, from[i], from[i].getToAddress());
		}
		w.write("]}");
		return false;
	}

	private void writeRef(Program p, Writer w, Reference r, Address other) throws Exception {
		w.write("{");
		RestJson.field(w, "address", RestAddr.key(other), true);
		RestJson.field(w, "address_display", other.toString(), false);
		RestJson.field(w, "type", r.getReferenceType().getName(), false);
		RestJson.bool(w, "is_call", r.getReferenceType().isCall(), false);
		RestJson.bool(w, "is_jump", r.getReferenceType().isJump(), false);
		RestJson.bool(w, "is_data", r.getReferenceType().isData(), false);
		RestJson.field(w, "source", r.getSource().toString(), false);
		// GhidraScript.getFunctionContaining is exactly this, and a Task is not
		// a GhidraScript.
		Function fn = p.getListing().getFunctionContaining(other);
		if (fn != null) {
			RestJson.field(w, "function", fn.getName(), false);
			RestJson.field(w, "function_address", RestAddr.key(fn.getEntryPoint()), false);
		}
		w.write("}");
	}

	// --------------------------------------------------------------- memory

	private void exportMemory(Program p) throws Exception {
		c.stage("memory");
		File memDir = c.dir("memory");
		Memory mem = p.getMemory();
		Writer w = c.open("memory/index.json");
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
			RestJson.field(w, "name", b.getName(), true);
			RestJson.field(w, "start", RestAddr.key(b.getStart()), false);
			RestJson.field(w, "start_display", b.getStart().toString(), false);
			RestJson.field(w, "end", RestAddr.key(b.getEnd()), false);
			RestJson.num(w, "size", b.getSize(), false);
			RestJson.bool(w, "read", b.isRead(), false);
			RestJson.bool(w, "write", b.isWrite(), false);
			RestJson.bool(w, "execute", b.isExecute(), false);
			RestJson.bool(w, "volatile", b.isVolatile(), false);
			RestJson.bool(w, "initialized", b.isInitialized(), false);
			RestJson.bool(w, "overlay", b.isOverlay(), false);
			RestJson.field(w, "type", b.getType().toString(), false);
			RestJson.field(w, "source", b.getSourceName(), false);
			RestJson.field(w, "file", file, false);
			RestJson.num(w, "bytes_exported", written, false);
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
		c.stage("decompiled");
		c.dir("decompiled");

		DecompInterface di = RestDecomp.open(c, p);
		if (di == null) {
			Writer idx = c.open("decompiled/index.json");
			idx.write("[]");
			idx.close();
			return;
		}

		Writer idx = c.open("decompiled/index.json");
		idx.write("[");
		boolean first = true;
		int seen = 0;
		// Externals are skipped below and the cap stops the walk early, so the
		// number worth reporting is neither the function count nor the cap.
		c.log("decompiling 0/" + Math.min(countLocalFunctions, maxDecompileFuncs));
		try {
			FunctionIterator it = p.getListing().getFunctions(true);
			while (it.hasNext() && !c.cancelled()) {
				Function f = it.next();
				if (f.isExternal()) {
					continue;
				}
				seen++;
				if (seen > maxDecompileFuncs) {
					c.log("decompile cap " + maxDecompileFuncs + " reached");
					break;
				}

				RestDecomp.Out out = RestDecomp.write(c, di, f, decompileTimeout);
				if (out.ok) {
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
				RestJson.field(idx, "address", RestAddr.key(f.getEntryPoint()), true);
				RestJson.field(idx, "name", f.getName(), false);
				RestJson.bool(idx, "ok", out.ok, false);
				RestJson.num(idx, "length", out.length, false);
				idx.write("}");

				if (seen % 200 == 0) {
					c.log("decompiled " + countDecompiled + "/" + seen);
				}
			}
		}
		finally {
			di.dispose();
			idx.write("]");
			idx.close();
		}
	}

	// --------------------------------------------------------------- disasm

	// One instruction listing per function, laid out like the decompiled set:
	// disasm/<addr>.json plus an index. Nearly free next to decompilation --
	// the instructions are already in the listing, this only serialises them.
	private void exportDisasm(Program p) throws Exception {
		c.stage("disasm");
		c.dir("disasm");
		Listing listing = p.getListing();

		Writer idx = c.open("disasm/index.json");
		idx.write("[");
		boolean firstFn = true;
		try {
			FunctionIterator it = listing.getFunctions(true);
			while (it.hasNext() && !c.cancelled()) {
				Function f = it.next();
				if (f.isExternal()) {
					// no body to disassemble; the thunk that calls it has one
					continue;
				}
				int n = RestDisasm.writeFunction(c, listing, f, maxDisasmInstructions);
				countInstructions += n;

				if (!firstFn) {
					idx.write(",");
				}
				firstFn = false;
				idx.write("{");
				RestJson.field(idx, "address", RestAddr.key(f.getEntryPoint()), true);
				RestJson.field(idx, "name", f.getName(), false);
				RestJson.num(idx, "count", n, false);
				idx.write("}");
			}
		}
		finally {
			idx.write("]");
			idx.close();
		}
	}

	// -------------------------------------------------------------- summary

	private void exportSummary(Program p) throws Exception {
		c.stage("summary");
		Writer w = c.open("summary.json");
		w.write("{");
		RestJson.field(w, "name", p.getName(), true);
		RestJson.field(w, "executable_path", p.getExecutablePath(), false);
		RestJson.field(w, "executable_format", p.getExecutableFormat(), false);
		RestJson.field(w, "md5", p.getExecutableMD5(), false);
		RestJson.field(w, "sha256", p.getExecutableSHA256(), false);
		RestJson.field(w, "language", p.getLanguageID().getIdAsString(), false);
		RestJson.field(w, "processor", p.getLanguage().getProcessor().toString(), false);
		RestJson.field(w, "endian", p.getLanguage().isBigEndian() ? "big" : "little", false);
		RestJson.num(w, "address_size", p.getDefaultPointerSize() * 8, false);
		RestJson.field(w, "compiler_spec",
			p.getCompilerSpec().getCompilerSpecID().getIdAsString(), false);
		RestJson.field(w, "image_base", RestAddr.key(p.getImageBase()), false);
		RestJson.field(w, "min_address", RestAddr.key(p.getMinAddress()), false);
		RestJson.field(w, "max_address", RestAddr.key(p.getMaxAddress()), false);
		RestJson.field(w, "creation_date", String.valueOf(p.getCreationDate()), false);
		RestJson.field(w, "ghidra_version", Application.getApplicationVersion(), false);
		RestJson.num(w, "memory_bytes_exported", bytesExported, false);

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
			w.write(RestJson.quoted(cc));
		}
		w.write("]");

		w.write(",\"entry_points\":[");
		List<String> eps = new ArrayList<String>();
		AddressIterator it = p.getSymbolTable().getExternalEntryPointIterator();
		while (it.hasNext() && eps.size() < 64) {
			eps.add(RestAddr.key(it.next()));
		}
		for (int i = 0; i < eps.size(); i++) {
			if (i > 0) {
				w.write(",");
			}
			w.write(RestJson.quoted(eps.get(i)));
		}
		w.write("]");

		w.write("}");
		w.close();
	}
}
