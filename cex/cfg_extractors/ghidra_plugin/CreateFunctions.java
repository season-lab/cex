import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.lang.Thread;

import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;

public class CreateFunctions extends HeadlessScript {
	Language lang;

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
		// disassemble(addr);
		return true;
	}

	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length == 0) {
			System.err.println("Missing filename");
			return;
		}

		lang = currentProgram.getLanguage();
		AddressSpace as = lang.getDefaultSpace();

		boolean at_least_one_new = false;
		String path = args[0];
		BufferedReader reader;
		try {
			reader = new BufferedReader(new FileReader(path));
			String line = reader.readLine();
			while (line != null) {
				Long addr = Long.parseLong(line.strip().substring(2), 16);
				if (createIfMissing(as.getAddress(addr)))
					at_least_one_new = true;

				// read next line
				line = reader.readLine();
			}
			reader.close();
		} catch (IOException e) {
			System.err.println(path + " is not a valid filename");
		}

		// analyzeChanges(currentProgram);
		if (at_least_one_new)
			printf("[OUT] OK\n");
		else
			printf("[OUT] KO\n");
	}
}
