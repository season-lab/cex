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
import java.util.Stack;

import generic.stl.Pair;

import java.util.HashSet;
import java.util.Set;

public class ExportCFG extends HeadlessScript {

    public void run() throws Exception {

        // Get the output file from the command line argument
        String[] args = getScriptArgs();
        String path   = "/dev/shm/cfg.json";
        if (args.length == 0) {
            System.err.println("Using /dev/shm/cfg.json as default path");
        } else {
            path = args[0];
        }

        printf("[DEBUG] Output file: %s\n", path); // DEBUG
        FileOutputStream fout;
        try {
            fout = new FileOutputStream(path);
        } catch (Exception e) {
            printf("Failed opening output file: Exception %s\n", e.toString());
            return;
        }
        PrintStream pout = new PrintStream(fout);

        // The actual thing
        SimpleBlockModel model = new SimpleBlockModel(currentProgram);

        Listing listing = currentProgram.getListing();

        HashSet<Long> external_functions = new HashSet<>();
        FunctionIterator iter_ext_functions = listing.getExternalFunctions();
        while (iter_ext_functions.hasNext() && !monitor.isCancelled()) {
            Function f = iter_ext_functions.next();
            for (Address a : f.getFunctionThunkAddresses())
                external_functions.add(a.getOffset());
        }

        FunctionIterator iter_functions = listing.getFunctions(true);

        boolean first_iter_functions = true;
        pout.format("[\n");
        while (iter_functions.hasNext() && !monitor.isCancelled()) {
            Function f = iter_functions.next();
            // if (f.isExternal() || f.isThunk()) {
            //     continue;
            // }

            if (!first_iter_functions)
                pout.format(" },\n");
            else
                first_iter_functions = false;

            pout.format(" {\n");
            pout.format("  \"name\": \"%s\",\n", f.getName());
            pout.format("  \"addr\": \"%#x\",\n", f.getEntryPoint().getOffset());
            pout.format("  \"is_returning\" : \"%s\",\n", f.hasNoReturn() ? "false" : "true");
            pout.format("  \"blocks\": [\n");
            CodeBlock entry_block  = model.getCodeBlockAt(f.getEntryPoint(), monitor);
            if (entry_block == null) {
                pout.format("  ]\n");
                continue;
            }

            Stack<CodeBlock> stack = new Stack<>();
            Set<CodeBlock> visited = new HashSet<>();
            stack.push(entry_block);

            while (!stack.empty()) {
                CodeBlock block = stack.pop();
                visited.add(block);

                Set<Pair<Address, Address>> call_successors = new HashSet<>();

                pout.format("    {\n");
                pout.format("      \"addr\" : \"%#x\",\n", block.getFirstStartAddress().getOffset());
                pout.format("      \"instructions\" : [\n", block.getFirstStartAddress().getOffset());
                InstructionIterator iter = currentProgram.getListing().getInstructions(block, true);
                while (iter.hasNext()) {
                    Instruction inst = iter.next();
                    pout.format("        { \"addr\": \"%#x\", \"size\": %d, \"mnemonic\" : \"%s\" }", inst.getAddress().getOffset(), inst.getLength(), inst.toString());
                    if (iter.hasNext())
                        pout.format(",\n");
                    else
                        pout.format("\n");

                    FlowType ft = inst.getFlowType();
                    if (ft != null && ft.isCall()) {
	                    for (Address dst : inst.getFlows()) {
	                    	call_successors.add(new Pair<>(dst, inst.getAddress()));
	                    }
                    }
                }
                pout.format("      ],\n");

                pout.format("      \"successors\" : [\n");
                boolean first_iter_insts = true;
                CodeBlockReferenceIterator succ_iter = block.getDestinations(monitor);
                while (succ_iter.hasNext()) {
                    CodeBlockReference succ_ref = succ_iter.next();
                    if (succ_ref.getFlowType().isCall())
                        continue;

                    if (!first_iter_insts)
                        pout.format(",\n");
                    else
                        first_iter_insts = false;

                    CodeBlock succ = succ_ref.getDestinationBlock();
                    if (!visited.contains(succ) && succ != null)
                        stack.push(succ);
                    pout.format("        \"%#x\"", succ.getFirstStartAddress().getOffset());
                }
                pout.format("\n");
                pout.format("      ],\n");

                pout.format("      \"calls\" : [\n");
                Iterator<Pair<Address, Address>> calls = call_successors.iterator();
                while(calls.hasNext()) {
                    Pair<Address, Address> call = calls.next();
                    if (external_functions.contains(call.first.getOffset())) {
                    	Function ext_f = getFunctionAt(call.first);
                    	if (ext_f != null) {
                    		pout.format("        { \"name\": \"%s\", \"callsite\" : \"%#x\", \"type\" : \"external\" }",
    								ext_f.getName(), call.second.getOffset());
                    	}
                    } else {
                    	pout.format("        { \"offset\": \"%#x\", \"callsite\" : \"%#x\", \"type\" : \"normal\" }",
                    			call.first.getOffset(), call.second.getOffset());
                    }
                    if (calls.hasNext())
                        pout.format(",\n");
                    else
                        pout.format("\n");
                }
                pout.format("      ]\n");

                if (stack.empty())
                    pout.format("    }\n");
                else
                    pout.format("    },\n");
            }
            pout.format("  ]\n");
        }
        if (!first_iter_functions)
            pout.format(" }\n");
        pout.format("]\n");

        fout.close();
        pout.close();
    }
}
