// Writes bytes into an already-analysed program and re-exports the artifacts
// the change can be seen in. Run against the *kept* project of an existing
// job, exactly like the signature task:
//
//   analyzeHeadless <proj> ghidrarest -process -noanalysis \
//       -postScript RestScript.java patch <outdir> <opsFile> <resultFile> [timeoutSec]
//
// Why this exists: the other way to get Ghidra to look at patched bytes is to
// submit the patched file as a new job, which on a 239 MiB target costs a
// second 1.1 GB of disk and eight minutes of analysis for the sake of four
// changed bytes. The program in the project already knows everything except
// those four bytes. So: clear the affected code units, write the bytes,
// re-disassemble the one function, re-decompile it and its callers. Cost is a
// JVM start and one decompile.
//
// ops.tsv columns: <address key><TAB><hex bytes>
// Hex is contiguous lowercase pairs, no separators: `9090909090`. The address
// is where the first byte lands; it does not have to be a function entry.
//
// result.tsv `before` is what those bytes were a moment ago -- the server
// records it, and it is the only thing that makes reverting a patch possible,
// since Ghidra has no undo across processes. On success `message` carries the
// entry point of the function the patch landed in.
//
// Artifacts rewritten under <outdir>:
//   functions.json            whole file (bodies and sizes move when code does)
//   disasm/<addr>.json        the patched functions -- instructions did change
//   decompiled/<addr>.json    the patched functions and their callers
//
// Deliberately NOT rewritten: disasm/index.json and decompiled/index.json (the
// `count`/`length` fields go stale for the rewritten functions and nothing
// reads them for correctness), summary.json, strings/symbols/imports/exports
// (a byte patch inside a function body does not move them).
//
//@category ghidra-rest
import java.io.File;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

public class TaskPatch implements Task {

	@Override
	public String name() {
		return "patch";
	}

	@Override
	public String usage() {
		return "<outdir> <opsFile> <resultFile> [decompileTimeoutSec]";
	}

	@Override
	public String logTag() {
		return "ApplyPatch";
	}

	private Ctx c;
	private int decompileTimeout = 60;

	@Override
	public void run(Ctx ctx, String[] args) throws Exception {
		this.c = ctx;
		if (args.length < 2) {
			throw new IllegalArgumentException("usage: RestScript patch " + usage());
		}
		File opsFile = new File(args[0]);
		File resultFile = new File(args[1]);
		if (args.length > 2) {
			decompileTimeout = Integer.parseInt(args[2]);
		}

		Program p = c.program;
		List<RestOps.Op> ops = RestOps.read(opsFile, 2);
		c.log("program=" + p.getName() + " ops=" + ops.size());

		// Functions whose disassembly changed, and -- through them -- whose
		// decompilation did. Callers are added on top for the decompiler only:
		// a caller's instructions are untouched, but its C text can name the
		// callee and change when the callee does.
		Set<Address> patched = new LinkedHashSet<Address>();
		Set<Address> redecompile = new LinkedHashSet<Address>();

		for (RestOps.Op op : ops) {
			apply(p, op, patched, redecompile);
		}

		RestOps.writeResult(resultFile, ops);

		if (!patched.isEmpty()) {
			// Bodies and sizes move when code does, so the whole listing walk
			// is rewritten. No decompiler involved: it is cheap.
			RestFunc.exportAll(c, p, false);
			exportDisasmSubset(p, patched);
			RestDecomp.writeSubset(c, p, redecompile, decompileTimeout);
		}

		c.log("done applied=" + RestOps.countOk(ops) + "/" + ops.size() +
			" redisassembled=" + patched.size() + " redecompiled=" + redecompile.size());
	}

	// ------------------------------------------------------------- applying

	private void apply(Program p, RestOps.Op op, Set<Address> patched, Set<Address> redecompile) {
		byte[] want = RestDisasm.unhex(op.col(0).toLowerCase());
		if (want == null) {
			// Reported rather than dropped: a client that sent nonsense
			// deserves a line saying so, not silence.
			op.message = "bytes are not contiguous hex pairs";
			return;
		}

		Address start;
		try {
			start = p.getAddressFactory().getAddress(op.key);
		}
		catch (Exception e) {
			op.message = "cannot parse address " + op.key;
			return;
		}
		if (start == null) {
			op.message = "cannot parse address " + op.key;
			return;
		}

		Memory mem = p.getMemory();
		MemoryBlock blk = mem.getBlock(start);
		if (blk == null) {
			op.message = "no memory at " + op.key;
			return;
		}
		if (!blk.isInitialized()) {
			// .bss and friends have no bytes on disk to patch.
			op.message = "memory at " + op.key + " is uninitialized";
			return;
		}

		Address end;
		try {
			end = start.add(want.length - 1);
		}
		catch (Exception e) {
			op.message = "patch runs past the end of the address space";
			return;
		}
		if (!blk.contains(end)) {
			op.message = "patch runs past the end of block " + blk.getName();
			return;
		}

		byte[] before = new byte[want.length];
		try {
			mem.getBytes(start, before);
		}
		catch (Exception e) {
			op.message = "cannot read the bytes being replaced: " + RestOps.rootMessage(e);
			return;
		}
		op.before = RestDisasm.hex(before);

		Function existing = p.getListing().getFunctionContaining(start);
		String func = existing == null ? "" : RestAddr.key(existing.getEntryPoint());

		if (Arrays.equals(before, want)) {
			// Already these bytes. Applying is a no-op, and re-disassembling
			// would be work for nothing -- but it is a success, not an error:
			// the caller asked for a state and the program is in it.
			op.ok = true;
			op.message = func;
			return;
		}

		// Clearing is per range rather than min..max: a function body can be
		// non-contiguous, and the gap between two of its ranges may belong to
		// a different function that has no business being cleared.
		AddressSet scope = new AddressSet(start, end);
		Address from = start;
		if (existing != null) {
			scope.add(existing.getBody());
			from = existing.getEntryPoint();
		}

		int tx = p.startTransaction("ghidra-rest: patch " + op.key);
		boolean ok = false;
		try {
			Listing listing = p.getListing();
			for (AddressRange r : scope) {
				listing.clearCodeUnits(r.getMinAddress(), r.getMaxAddress(), false);
			}
			mem.setBytes(start, want);

			// Follow flow, but only inside the range that was cleared: a patch
			// that turns a byte into a jump somewhere else must not drag a
			// disassembly sweep across the rest of the program.
			DisassembleCommand cmd = new DisassembleCommand(from, scope, true);
			if (!cmd.applyTo(p, c.monitor)) {
				String msg = cmd.getStatusMsg();
				throw new IllegalStateException(
					msg == null || msg.isEmpty() ? "Ghidra could not disassemble the patched bytes"
							: msg);
			}

			if (existing != null) {
				Function again = listing.getFunctionAt(existing.getEntryPoint());
				if (again == null) {
					// Clearing the body took the function with it; put it back
					// so the address keeps its identity across the patch.
					new CreateFunctionCmd(existing.getEntryPoint()).applyTo(p, c.monitor);
					again = listing.getFunctionAt(existing.getEntryPoint());
				}
				if (again != null) {
					// The body is whatever flows from the entry point now,
					// which is not what it was before the patch.
					CreateFunctionCmd.fixupFunctionBody(p, again, c.monitor);
				}
			}
			ok = true;
		}
		catch (Throwable t) {
			// Half a patch -- bytes written, code units gone -- is worse than
			// none, so the whole transaction goes back.
			op.message = RestOps.rootMessage(t);
		}
		finally {
			p.endTransaction(tx, ok);
		}
		if (!ok) {
			return;
		}

		op.ok = true;
		Function f = p.getListing().getFunctionContaining(start);
		op.message = f == null ? "" : RestAddr.key(f.getEntryPoint());
		if (f != null) {
			patched.add(f.getEntryPoint());
			redecompile.add(f.getEntryPoint());
			for (Function caller : f.getCallingFunctions(c.monitor)) {
				redecompile.add(caller.getEntryPoint());
			}
		}
	}

	// ------------------------------------------------------------ re-export

	// Same document shape as the export task writes per function. No cap: this
	// function was already exported once under the real one.
	private void exportDisasmSubset(Program p, Set<Address> addrs) throws Exception {
		Listing listing = p.getListing();
		for (Address a : addrs) {
			if (c.cancelled()) {
				break;
			}
			Function f = listing.getFunctionAt(a);
			if (f == null || f.isExternal()) {
				continue;
			}
			RestDisasm.writeFunction(c, listing, f, Integer.MAX_VALUE);
		}
	}
}
