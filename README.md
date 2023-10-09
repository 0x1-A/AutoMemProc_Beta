# AutoMemProc

AutoMemProc is a tool designed to simplify and streamline the process of analyzing memory dumps. Its main goal is to act  as an interface for the Volatility 3 framework version 2.5.0, enhancing the user experience with automation and user-friendly prompts.

Key Features:
- User-friendly interface: AutoMemProc provides clear prompts, asking users to input paths to memory images or choose from 
  existing images.
- Automatic Image Detection: Upon providing a directory, the tool lists all memory image files present, allowing users to 
  easily select the image they wish to analyze.
- Saved Paths: The tool has the capability to remember certain paths, such as the path to the Volatility executable, to 
  speed up repeated analyses.
- Plugin Interface: Once an image is chosen, the tool provides a menu system, letting users select and run various - 
  Volatility plugins directly from the interface.
- Error Handling: AutoMemProc contains checks to handle errors gracefully, such as empty paths or invalid inputs, and guide 
  users in correcting them.

Target Audience:
 - Digital forensics professionals or researchers who often analyze memory dumps.
   Incident responders looking to quickly triage potentially compromised systems.
   Educators or students in cybersecurity courses where memory analysis is a topic.

Optimized Environment:
- AutoMemProc is optimized for Unix environments and may not function as intended in other operating systems.

## Key Point

- Ensure proper permissions are granted for this tool to execute without errors.
- The results of the plugins are not displayed directly in the terminal. Instead, they are saved as .txt files in the same directory where the image file is stored.
- The Process Dump Plugin, create a folder in the same location as the image file to store its outputs.

## Recommendtion

- Store automemproc.ps1 in the same folder as the imagefile for quick detection.

## Contact

For information or requests, contact:

Issue/Support: 
Twitter: @atiahlaoufi
