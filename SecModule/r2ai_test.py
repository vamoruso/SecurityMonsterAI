import os

import r2pipe


try:
    print(os.path.exists('C:/tmp/a.exe'))  # Deve restituire True
    r2 = r2pipe.open('C:/tmp/a.exe', flags=['-2'])
   # Initialize analysis
    print("[+] Analyzing binary with 'aaa'...")
    r2.cmd('aaa')  # Analisi automatica
    functions = r2.cmd('afl')  # Lista funzioni
    print("[function]" +functions)

    r2.cmd("s fcn.00543a65")
    function_code = r2.cmd('pdf')
    print("[+] "+ function_code)

    variabili = r2.cmd('iz')
    print("[variabili] " + variabili)

    disassemblaggio = r2.cmd('pdf')
    print("[dissa] " + disassemblaggio)

    pseudo = r2.cmd('pdc')
    print("[pseudo] " + pseudo)

    pseudo = r2.cmd('pdgo')
    print("[pdda] " + pseudo)

    # Ensure r2ai is loaded
    load_result = r2.cmd("r2ai")
    print("[r2ai] " + load_result)

except Exception as e:
    raise RuntimeError(f"❌ Error during analysis: {str(e)}")

finally:
    r2.quit()