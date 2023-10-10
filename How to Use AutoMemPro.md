## How to used AutoMemProc? in 3 steps .. 


**Tool Execution**

   ```shell
   pwsh automemproc.ps1
   ```

**Type Image File Path** (You dont need to do this step if Tool & ImageFile in the same folder)

   Example:

   ```note
   /home/test/Desktop/memory/
   ```

   OR 

   ```note
   /home/test/Desktop/memory/memory.img
   ```

   OR 

   ```note
   ~/Desktop/memory/
   ```

**Type Volatility Path** (After entering the path, select 'y' to save it in a '.txt' file. This ensures you won't need to re-enter the path in future uses.)
   
   Example:

   ```note
   /opt/volatility3.2.5.1/vol.py
   ```

... Just pick a number from displayed list and follow the prompt ;)

## Extra 

**Commands** 

[timeline] Executes the Timeline plugin, provides a timeline of events."
[dump -p]  Dump a process along with its associated content using the 'dumpfile' plugin."

**Background Jobs**

[job -s] List Plugins with Background Job feature."
[job -all] Check the status of background jobs initiated by this tool."
[job -r] Remove background jobs initiated by this tool."

**Miscellaneous** 
[help] Help Message"
[status] Shows current supported plugin in the tool"
[show] Show currently selected live image."
[clear] Clear the terminal."
[back] To return to previous list"

**Notes**
    - Please ensure you do not exit the tool until your job completes, as exiting while a job is active will terminate the job."
    - For a background job running status using Linux terminal, you can identify it using the 'ps -ef'"
   
  We hope this tool simplifies your memory analysis process. Please enjoy using the tool, and do let us know if you have any suggestions