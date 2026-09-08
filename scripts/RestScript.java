// The only script analyzeHeadless is ever pointed at.
//
//   -postScript RestScript.java <task> <outdir> [task args...]
//
// It resolves the task name against RestRegistry and hands off. Two names are
// handled here rather than by a task, because neither needs a program:
//
//   tasks      print the registry as JSON, so the server can discover what
//              this image supports instead of hardcoding a second list
//   selftest   what docker/warmup.sh runs at image build time: it forces the
//              whole script bundle to compile, so a syntax error fails the
//              build rather than someone's first job
//
// Everything of substance lives in TaskExport / TaskSignature / TaskPatch and
// the Rest* helpers they share.
//
//@category ghidra-rest
import java.io.File;

import ghidra.app.script.GhidraScript;

public class RestScript extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 1) {
			throw new IllegalArgumentException(
				"usage: RestScript <task> <outdir> [args...]; tasks: " + RestRegistry.names());
		}
		String name = args[0];

		if ("tasks".equals(name)) {
			println(RestRegistry.asJson());
			return;
		}
		if ("selftest".equals(name)) {
			// Reaching this line means every class in the bundle compiled and
			// every task in the registry constructed.
			println("RestScript: selftest ok tasks=" + RestRegistry.names());
			return;
		}

		Task task = RestRegistry.get(name);
		if (task == null) {
			throw new IllegalArgumentException(
				"unknown task \"" + name + "\"; tasks: " + RestRegistry.names());
		}
		if (args.length < 2) {
			throw new IllegalArgumentException("usage: RestScript " + name + " " + task.usage());
		}

		File outDir = new File(args[1]);
		Ctx.mkdirs(outDir);

		String[] rest = new String[args.length - 2];
		System.arraycopy(args, 2, rest, 0, rest.length);

		// monitor is protected on GhidraScript and the tasks are not in its
		// package, so it is handed over explicitly here.
		task.run(new Ctx(this, currentProgram, outDir, monitor, task.logTag()), rest);
	}
}
