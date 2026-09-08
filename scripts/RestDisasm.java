// One function's instruction listing, and the per-instruction formatting the
// export task and the patch task both need.
//
//@category ghidra-rest
import java.io.Writer;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;

public final class RestDisasm {

	private RestDisasm() {
	}

	// Writes disasm/<addr>.json for one function and returns how many
	// instructions went in.
	//
	// maxInstructions bounds one function: a runaway body should not write a
	// gigabyte of JSON. The patch task passes Integer.MAX_VALUE, because it is
	// rewriting a function that was already exported once under the real cap.
	public static int writeFunction(Ctx c, Listing listing, Function f, int maxInstructions)
			throws Exception {
		String k = RestAddr.key(f.getEntryPoint());
		AddressSetView body = f.getBody();

		Writer fw = c.open("disasm/" + RestAddr.fileKey(k) + ".json");
		fw.write("{");
		RestJson.field(fw, "address", k, true);
		RestJson.field(fw, "address_display", f.getEntryPoint().toString(), false);
		RestJson.field(fw, "name", f.getName(), false);
		fw.write(",\"instructions\":[");
		int n = 0;
		try {
			InstructionIterator iit = listing.getInstructions(body, true);
			while (iit.hasNext() && !c.cancelled() && n < maxInstructions) {
				Instruction ins = iit.next();
				if (n > 0) {
					fw.write(",");
				}
				fw.write("{");
				RestJson.field(fw, "address", RestAddr.key(ins.getAddress()), true);
				RestJson.field(fw, "address_display", ins.getAddress().toString(), false);
				RestJson.field(fw, "bytes", hexBytes(ins), false);
				RestJson.field(fw, "mnemonic", ins.getMnemonicString(), false);
				RestJson.field(fw, "operands", operandText(ins), false);
				RestJson.field(fw, "text", ins.toString(), false);
				RestJson.field(fw, "comment", commentText(listing, ins), false);
				RestJson.num(fw, "length", ins.getLength(), false);
				RestJson.bool(fw, "is_call", ins.getFlowType().isCall(), false);
				RestJson.bool(fw, "is_jump", ins.getFlowType().isJump(), false);
				RestJson.bool(fw, "is_terminal", ins.getFlowType().isTerminal(), false);
				RestJson.field(fw, "flow", flowTarget(ins), false);
				fw.write("}");
				n++;
			}
		}
		finally {
			// Closed here so a listing that throws part way still leaves a
			// parseable document behind.
			fw.write("]");
			RestJson.num(fw, "count", n, false);
			RestJson.bool(fw, "truncated", n >= maxInstructions, false);
			fw.write("}");
			fw.close();
		}
		return n;
	}

	public static String hexBytes(Instruction ins) {
		try {
			return hex(ins.getBytes());
		}
		catch (Exception e) {
			return "";
		}
	}

	// Ghidra renders each operand separately; the joined form is what a listing
	// window shows to the right of the mnemonic.
	public static String operandText(Instruction ins) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < ins.getNumOperands(); i++) {
			if (i > 0) {
				sb.append(",");
			}
			sb.append(ins.getDefaultOperandRepresentation(i));
		}
		return sb.toString();
	}

	public static String commentText(Listing listing, Instruction ins) {
		String c = listing.getComment(CodeUnit.EOL_COMMENT, ins.getAddress());
		if (c == null) {
			c = listing.getComment(CodeUnit.PRE_COMMENT, ins.getAddress());
		}
		return c == null ? "" : c;
	}

	// Where a call or jump goes, when the target is a single known address.
	public static String flowTarget(Instruction ins) {
		Address[] flows = ins.getFlows();
		if (flows == null || flows.length != 1) {
			return "";
		}
		return RestAddr.key(flows[0]);
	}

	public static String hex(byte[] b) {
		StringBuilder sb = new StringBuilder(b.length * 2);
		for (int i = 0; i < b.length; i++) {
			sb.append(String.format("%02x", b[i] & 0xff));
		}
		return sb.toString();
	}

	// null rather than an exception: a client sending nonsense gets a line in
	// the result file saying so, and the other ops still run.
	public static byte[] unhex(String s) {
		if (s.length() == 0 || s.length() % 2 != 0) {
			return null;
		}
		byte[] b = new byte[s.length() / 2];
		for (int i = 0; i < b.length; i++) {
			int hi = Character.digit(s.charAt(i * 2), 16);
			int lo = Character.digit(s.charAt(i * 2 + 1), 16);
			if (hi < 0 || lo < 0) {
				return null;
			}
			b[i] = (byte) ((hi << 4) | lo);
		}
		return b;
	}
}
