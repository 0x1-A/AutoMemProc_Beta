## How to use AutoMemProc?


**1.Tool Execution**

   ```shell
   sudo pwsh automemproc.ps1
   ```

**2.Type Image File/folder Path** (You dont need to do this step if Tool & ImageFile in the same folder)

   Example:

   ```note
   /home/test/Desktop/memory/
   ```

   OR 

   ```note
   /home/test/Desktop/memory/memory.img
   ```


**3.Type Volatility Path** (After entering the path, select 'y' to save it in a '.txt' file. This ensures you won't need to re-enter the path in future uses.)
   
   Example:

   ```note
   /path/to/vol.py
   ```

... Just pick a number from displayed list and follow the prompt ;)

# Features 

## Commands

**- Unversial Command** 

  - [help]
     - Help Message
  - [status]
     - Shows current supported plugin in the tool"
  - [show]
     - Show currently selected live image."
  - [clear]
     - Clear the terminal."
  - [back]
     - To return to previous list"
       
**- These can be executed in the Plugin Categories Menu** 

  - [timeline]
    - Executes the Timeline plugin, provides a timeline of events."
  - [dump -p]
    - Dump a process along with its associated content using the 'dumpfile' plugin."
  - [job -s]
    - List Plugins with Background Job feature."
  - [job -all]
    - Check the status of background jobs initiated by this tool."
  - [job -r]
    - Remove background jobs initiated by this tool."
  
  **We hope this tool simplifies your memory analysis process. Please enjoy using the tool, and do let us know if you have any suggestions**
