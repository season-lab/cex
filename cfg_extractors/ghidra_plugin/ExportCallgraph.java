import ghidra.app.util.headless.HeadlessScript;

import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;

import java.io.PrintWriter;
import java.io.PrintStream;
import java.io.FileOutputStream;

import java.util.Iterator;
import java.util.Set;

public class ExportCallgraph extends HeadlessScript {

    public void run() throws Exception {

      // Get the output file from the command line argument
      String[] args = getScriptArgs();
      String path   = "/dev/shm/callgraph.json";
      if (args.length == 0) {
        System.err.println("Using /dev/shm/callgraph.json as default path");
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
      Listing listing = currentProgram.getListing();
      FunctionIterator iter_functions = listing.getFunctions(true);

      pout.format("[\n");
      while (iter_functions.hasNext() && !monitor.isCancelled()) {
        Function f = iter_functions.next();
        // if (f.isExternal() || f.isThunk()) {
        //   continue;
        // }

        pout.format(
          "  {\n"                  +
          "    \"name\": \"%s\",\n"  +
          "    \"addr\": \"%#x\",\n" +
          "    \"calls\": [\n",
            f.getName(), f.getEntryPoint().getOffset());

        Set<Function> called_functions = f.getCalledFunctions(monitor);
        Iterator<Function> iter_called = called_functions.iterator();
        while (iter_called.hasNext()) {
          Function called = iter_called.next();
          pout.format(
            "      \"%#x\"", called.getEntryPoint().getOffset());
          if (iter_called.hasNext())
            pout.format(",\n");
          else
            pout.format("\n");
        }

        if (iter_functions.hasNext())
          pout.format("    ]\n  },\n");
        else
          pout.format("    ]\n  }\n");
      }
      pout.format("]\n");

      fout.close();
      pout.close();
    }
}
