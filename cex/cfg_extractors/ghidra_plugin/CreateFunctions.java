import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Iterator;
import java.util.HashSet;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;

import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;

public class CreateFunctions extends HeadlessScript {
	Language lang;
	DecompInterface ifc;

	private boolean isARM() {
		return lang.getProcessor().toString().equals("ARM");
	}

	private void setThumb(Function fun) throws ContextChangeException {
		Register tmode_r = currentProgram.getRegister("TMode");
		if (currentProgram.getProgramContext().getRegisterValue(tmode_r, fun.getEntryPoint()).getUnsignedValueIgnoreMask().compareTo(BigInteger.ONE) == 0)
			return;

		Address min = fun.getBody().getMinAddress();
		Address max = fun.getBody().getMaxAddress();

		RegisterValue tmode_active = new RegisterValue(tmode_r, BigInteger.ONE);

		currentProgram.getProgramContext().setRegisterValue(min, max, tmode_active);
	}

	private boolean createIfMissing(Address addr) throws Exception {
		boolean is_thumb = false;
		if (isARM() && (addr.getOffset() % 2 == 1)) {
			addr = addr.subtract(1);
			is_thumb = true;
		}

		Function f = getFunctionAt(addr);
		if (f != null)
			return false;

		f = createFunction(addr, null);
		if (f == null)
			// Weird, but works
			f = createFunction(addr, null);

		if (f == null)
			return false;

		if (is_thumb)
			setThumb(f);

		return true;
	}

	private boolean processFunctionCalleesRecursive(Function f, HashSet<Function> processed) throws Exception {
		if (processed.contains(f))
			return false;
		processed.add(f);

		boolean created_at_least_one = false;
		DecompileResults dr = ifc.decompileFunction(f, 300, monitor);
		HighFunction h = dr.getHighFunction();
		if (h != null) {
			Iterator<PcodeOpAST> opcodes_iter = h.getPcodeOps();
			while (opcodes_iter.hasNext()) {
				PcodeOpAST op = opcodes_iter.next();
				if (op.getOpcode() != PcodeOp.CALL)
					continue;

				Address target = op.getInput(0).getAddress();
				created_at_least_one = created_at_least_one || createIfMissing(target);
				Function callee = getFunctionAt(target);
				if (callee != null)
					created_at_least_one = created_at_least_one || processFunctionCalleesRecursive(callee, processed);
			}
		}
		return created_at_least_one;
	}

	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length == 0) {
			System.err.println("Missing filename");
			return;
		}

		ifc = new DecompInterface();
		DecompileOptions opt = new DecompileOptions();
		ifc.setOptions(opt);
		ifc.openProgram(currentProgram);

		lang = currentProgram.getLanguage();
		AddressSpace as = lang.getDefaultSpace();

		boolean at_least_one_created = false;
		HashSet<Function> processed = new HashSet<>();

		String path = args[0];
		BufferedReader reader;
		try {
			reader = new BufferedReader(new FileReader(path));
			String line = reader.readLine();
			while (line != null) {
				Long addr = Long.parseLong(line.strip().substring(2), 16);
				at_least_one_created = at_least_one_created || createIfMissing(as.getAddress(addr));

				Function f = getFunctionAt(as.getAddress(addr));
				if (f != null)
					at_least_one_created = at_least_one_created || processFunctionCalleesRecursive(f, processed);

				// read next line
				line = reader.readLine();
			}
			reader.close();
		} catch (IOException e) {
			System.err.println(path + " is not a valid filename");
		}

		if (at_least_one_created)
			System.out.println("[OUTPUT_MSG] OK");
		else
			System.out.println("[OUTPUT_MSG] KO");
	}
}
