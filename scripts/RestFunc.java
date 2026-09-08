// One function's JSON record, and the whole-listing walk that writes
// functions.json.
//
// Shared because all three tasks write this file and the server serves
// whichever of them wrote it last -- a client cannot tell which did, so the
// shape has to be identical. It used to be identical by being copied three
// times.
//
//@category ghidra-rest
import java.io.Writer;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.StackFrame;

public final class RestFunc {

	private RestFunc() {
	}

	// Walks every function and writes functions.json. Returns {total, local},
	// which the export task needs: the decompile progress line counts local
	// functions, not the total.
	//
	// progress=true adds the periodic count lines. Only the export task wants
	// them -- an edit rewrites this file in well under a second.
	public static int[] exportAll(Ctx c, Program p, boolean progress) throws Exception {
		Listing listing = p.getListing();
		int total = 0;
		int local = 0;
		Writer w = c.open("functions.json");
		try {
			w.write("[");
			boolean first = true;
			FunctionIterator it = listing.getFunctions(true);
			while (it.hasNext() && !c.cancelled()) {
				Function f = it.next();
				if (!first) {
					w.write(",");
				}
				first = false;
				total++;
				if (!f.isExternal()) {
					local++;
				}
				write(c, w, f);
				if (progress && total % 500 == 0) {
					c.log("functions " + total);
				}
			}
			w.write("]");
		}
		finally {
			w.close();
		}
		if (progress) {
			// The periodic line counts in 500s, so it is a floor. This is the
			// total.
			c.log("functions total=" + total);
		}
		return new int[] { total, local };
	}

	public static void write(Ctx c, Writer w, Function f) throws Exception {
		Address entry = f.getEntryPoint();
		w.write("{");
		RestJson.field(w, "address", RestAddr.key(entry), true);
		RestJson.field(w, "address_display", entry.toString(), false);
		RestJson.field(w, "name", f.getName(), false);
		RestJson.field(w, "namespace", f.getParentNamespace().getName(true), false);
		RestJson.field(w, "signature", f.getSignature().getPrototypeString(), false);
		RestJson.field(w, "calling_convention", f.getCallingConventionName(), false);
		RestJson.field(w, "return_type", f.getReturnType().getDisplayName(), false);
		RestJson.num(w, "size", f.getBody().getNumAddresses(), false);
		RestJson.num(w, "parameter_count", f.getParameterCount(), false);
		RestJson.bool(w, "is_thunk", f.isThunk(), false);
		RestJson.bool(w, "is_external", f.isExternal(), false);
		RestJson.bool(w, "is_inline", f.isInline(), false);
		RestJson.bool(w, "has_varargs", f.hasVarArgs(), false);
		RestJson.bool(w, "no_return", f.hasNoReturn(), false);

		StackFrame frame = f.getStackFrame();
		if (frame != null) {
			RestJson.num(w, "stack_frame_size", frame.getFrameSize(), false);
		}

		w.write(",\"parameters\":[");
		Parameter[] params = f.getParameters();
		for (int i = 0; i < params.length; i++) {
			if (i > 0) {
				w.write(",");
			}
			w.write("{");
			RestJson.field(w, "name", params[i].getName(), true);
			RestJson.field(w, "type", params[i].getDataType().getDisplayName(), false);
			RestJson.num(w, "ordinal", params[i].getOrdinal(), false);
			w.write("}");
		}
		w.write("]");

		writeAddrList(w, "calls", f.getCalledFunctions(c.monitor));
		writeAddrList(w, "called_by", f.getCallingFunctions(c.monitor));
		w.write("}");
	}

	public static void writeAddrList(Writer w, String name, Set<Function> set) throws Exception {
		w.write(",\"" + name + "\":[");
		boolean first = true;
		for (Function f : set) {
			if (!first) {
				w.write(",");
			}
			first = false;
			w.write("{");
			RestJson.field(w, "address", RestAddr.key(f.getEntryPoint()), true);
			RestJson.field(w, "name", f.getName(), false);
			w.write("}");
		}
		w.write("]");
	}
}
