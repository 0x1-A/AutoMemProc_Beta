**How to used AutoMemProc?** in 3 steps .. 

 

1. Tool Execution

   ```shell
   pwsh automemproc.ps1
   ```

2. Type Image File Path

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

3) Type Volatility Path
   
   Example:

   ```note
   /opt/volatility3.2.5.1/vol.py
   ```

... You ready to use the tool. 



    Write-Host "... Just pick a number from displayed list and follow the prompt ;)"
    Write-Host ""
    
Write-Host "Commands:" -ForegroundColor Darkyellow
Write-Host ""

Write-Host "1} Plugins" -ForegroundColor Darkyellow
Write-Host "- " -NoNewline
Write-Host "[timeline]" -ForegroundColor yellow -NoNewline
Write-Host " Executes the Timeline plugin, provides a timeline of events."
Write-Host "- " -NoNewline
Write-Host "[dump -p]" -ForegroundColor yellow -NoNewline
Write-Host " Dump a process along with its associated content using the 'dumpfile' plugin."
Write-Host ""
Write-Host "2} Background Jobs" -ForegroundColor Darkyellow
Write-Host "- " -NoNewline
Write-Host "[job -s]" -ForegroundColor yellow -NoNewline
Write-Host " List Plugins with Background Job feature."
Write-Host "- " -NoNewline
Write-Host "[job -all]" -ForegroundColor yellow -NoNewline
Write-Host " Check the status of background jobs initiated by this tool."
Write-Host "- " -NoNewline
Write-Host "[job -r]" -ForegroundColor yellow -NoNewline
Write-Host " Remove background jobs initiated by this tool."
Write-Host ""
Write-Host "3} Miscellaneous" -ForegroundColor Darkyellow
Write-Host "- " -NoNewline
Write-Host "[help]" -ForegroundColor yellow -NoNewline
Write-Host " Help Message"

Write-Host "- " -NoNewline
Write-Host "[status]" -ForegroundColor yellow -NoNewline
Write-Host " Shows current supported plugin in the tool"

Write-Host "- " -NoNewline
Write-Host "[show]" -ForegroundColor yellow -NoNewline
Write-Host " Show currently selected live image."

Write-Host "- " -NoNewline
Write-Host "[clear]" -ForegroundColor yellow -NoNewline
Write-Host " Clear the terminal."

Write-Host "- " -NoNewline
Write-Host "[back]" -ForegroundColor yellow -NoNewline
Write-Host " To return to previous list"

Write-Host ""

    
    Write-Host "Notes:" -ForegroundColor DarkYellow
    Write-Host "- Please ensure you do not exit the tool until your job completes, as exiting while a job is active will terminate the job."
    Write-Host "- For a background job running status using Linux terminal, you can identify it using the 'ps -ef'"
    Write-Host ""
    
    Write-Host "We hope this tool simplifies your memory analysis process." -ForegroundColor Cyan
    Write-Host "Please enjoy using the tool, and do let us know if you have any suggestions" -ForegroundColor Cyan
}
