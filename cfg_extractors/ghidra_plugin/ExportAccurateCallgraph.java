import ghidra.app.util.headless.HeadlessScript;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;

import java.io.PrintStream;
import java.io.FileOutputStream;

import java.util.Iterator;

public class ExportAccurateCallgraph extends HeadlessScript {

	public void run() throws Exception {

		// Get the output file from the command line argument
		String[] args = getScriptArgs();
		String path = "/dev/shm/pcode_callgraph.json";
		if (args.length == 0) {
			System.err.println("Using /dev/shm/pcode_callgraph.json as default path");
		} else {
			path = args[0];
		}

		println(String.format("[DEBUG] Output file: %s", path)); // DEBUG
		FileOutputStream fout;
		try {
			fout = new FileOutputStream(path);
		} catch (Exception e) {
			printf("Failed opening output file: Exception %s\n", e.toString());
			return;
		}
		PrintStream pout = new PrintStream(fout);

		// The actual thing
		DecompInterface ifc = new DecompInterface();
		DecompileOptions opt = new DecompileOptions();
		ifc.setOptions(opt);
		ifc.openProgram(currentProgram);

		pout.format("[\n");
		Listing listing = currentProgram.getListing();
		FunctionIterator iter_functions = listing.getFunctions(true);
		while (iter_functions.hasNext() && !monitor.isCancelled()) {
			Function f = iter_functions.next();
			DecompileResults dr = ifc.decompileFunction(f, 300, monitor);
			HighFunction h = dr.getHighFunction();

			pout.format("  {\n" + "    \"name\": \"%s\",\n" + "    \"addr\": \"%#x\",\n" + "    \"calls\": [\n",
					f.getName(), f.getEntryPoint().getOffset());

			boolean need_comma = false;
			Iterator<PcodeOpAST> opcodes_iter = h.getPcodeOps();
			while (opcodes_iter.hasNext()) {
				PcodeOpAST op = opcodes_iter.next();
				if (op.getOpcode() != PcodeOp.CALL)
					continue;

				if (need_comma) {
					pout.format(",\n");
				} else {
					need_comma = true;
				}
				
				Address target = op.getInput(0).getAddress();

				pout.format("      \"%#x\"", target.getOffset());
			}

			if (iter_functions.hasNext())
				pout.format("\n    ]\n  },\n");
			else
				pout.format("\n    ]\n  }\n");
		}
		pout.format("]\n");

		fout.close();
		pout.close();
	}
}
